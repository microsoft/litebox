// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Socket-related syscalls, e.g., socket, bind, listen, etc.

use core::{
    mem::{offset_of, size_of},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use alloc::string::ToString;
use alloc::sync::Arc;
use litebox::{
    event::{
        Events, IOPollable,
        polling::TryOpError,
        wait::{WaitContext, WaitError},
    },
    fs::OFlags,
    net::{
        CloseBehavior, TcpOptionData,
        errors::AcceptError,
        socket_channel::{ChannelReadError, ChannelWriteError, NetworkProxy, SocketState},
    },
    platform::Instant as _,
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    AddressFamily, FileDescriptorFlags, IPProtocol, ReceiveFlags, SendFlags, ShutdownHow,
    SockFlags, SockType, SocketOption, SocketOptionName, TcpOption, UnixProtocol, UserMmsgHdr,
    UserMsgHdr, errno::Errno, signal::Signal,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::{
    file::TransferredFd,
    unix::{CSockUnixAddr, UnixSocket, UnixSocketAddr},
};
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

impl<Platform: ShimPlatform, FS: ShimFS> super::file::FilesState<Platform, FS> {
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

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
#[repr(C, packed)]
struct CSockInet6Addr {
    family: i16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

impl From<CSockInet6Addr> for SocketAddrV6 {
    fn from(c_addr: CSockInet6Addr) -> Self {
        SocketAddrV6::new(
            Ipv6Addr::from(c_addr.addr),
            u16::from_be(c_addr.port),
            u32::from_be(c_addr.flowinfo),
            // scope_id is a local interface index, not a wire quantity, so unlike
            // port/flowinfo it is never byte-swapped (see Linux's `struct sockaddr_in6`).
            c_addr.scope_id,
        )
    }
}

impl From<SocketAddrV6> for CSockInet6Addr {
    fn from(addr: SocketAddrV6) -> Self {
        CSockInet6Addr {
            family: AddressFamily::INET6 as i16,
            port: addr.port().to_be(),
            flowinfo: addr.flowinfo().to_be(),
            addr: addr.ip().octets(),
            scope_id: addr.scope_id(),
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "each field mirrors one independent Linux setsockopt(2) flag"
)]
pub(super) struct SocketOptions {
    pub(super) reuse_address: bool,
    pub(super) keep_alive: bool,
    pub(super) broadcast: bool,
    /// `SO_PASSCRED`: deliver the sender's `SCM_CREDENTIALS` with every
    /// `recvmsg`. Only `AF_UNIX` sockets honour it.
    pub(super) pass_cred: bool,
    pub(super) receive_ipv4_returned_options: bool,
    pub(super) receive_ipv4_ttl: bool,
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

#[derive(Clone, Copy, Default)]
struct IcmpProxySocket {
    peer: Option<Ipv4Addr>,
}

impl<Platform: ShimPlatform> Clone for SocketProxy<Platform> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(super) enum SocketOptionValue {
    Timeout(Option<core::time::Duration>),
    U32(u32),
}

/// What one receive delivered: the data length plus the ancillary payload a `recvmsg`
/// turns into control messages.
struct Received<Platform: ShimPlatform, FS: ShimFS> {
    size: usize,
    /// Descriptors transferred with the data (`SCM_RIGHTS`).
    rights: alloc::vec::Vec<TransferredFd<Platform, FS>>,
    /// The sender's credentials (`SCM_CREDENTIALS`), present only when the receiving
    /// `AF_UNIX` socket has `SO_PASSCRED` set.
    credentials: Option<litebox_common_linux::Ucred>,
}

/// Appends one control message to `control` the way Linux's `put_cmsg` fills a user buffer
/// of `capacity` bytes: a header that no longer fits is dropped, a payload that no longer
/// fits is cut short (its `cmsg_len` says how much was written), and the cursor advances by
/// `CMSG_SPACE` or to the end of the buffer, whichever comes first. Returns whether anything
/// was truncated (`MSG_CTRUNC`).
fn put_cmsg(
    control: &mut alloc::vec::Vec<u8>,
    capacity: usize,
    level: u32,
    cmsg_type: u32,
    data: &[u8],
) -> bool {
    const CMSG_HEADER_LEN: usize = size_of::<usize>() + 2 * size_of::<u32>();
    let start = control.len();
    let remaining = capacity.saturating_sub(start);
    if remaining < CMSG_HEADER_LEN {
        return true;
    }
    let cmsg_len = CMSG_HEADER_LEN + data.len();
    let truncated = remaining < cmsg_len;
    let write_len = cmsg_len.min(remaining);
    control.extend_from_slice(&write_len.to_ne_bytes());
    control.extend_from_slice(&level.to_ne_bytes());
    control.extend_from_slice(&cmsg_type.to_ne_bytes());
    control.extend_from_slice(&data[..write_len - CMSG_HEADER_LEN]);
    let cmsg_space = (cmsg_len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
    control.resize(start + cmsg_space.min(remaining), 0);
    truncated
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
        // Entry-scoped, like `SocketOptions`/`SocketOFlags`: `SO_TYPE` belongs to the open file
        // description, so a `dup`'d descriptor must still answer as a socket after the original
        // fd is closed. (`duplicate` deliberately does not copy fd-scoped metadata.)
        let old = dt.set_entry_metadata(fd, sock_type);
        assert!(old.is_none());
        let old = dt.set_entry_metadata(fd, SocketOFlags(status));
        assert!(old.is_none());

        let proxy = match sock_type {
            SockType::Stream => {
                let proxy = litebox::net::socket_channel::StreamSocketChannel::new();
                NetworkProxy::Stream(proxy)
            }
            SockType::Datagram => {
                let proxy = litebox::net::socket_channel::DatagramSocketChannel::new();
                NetworkProxy::Datagram(proxy)
            }
            SockType::Raw => NetworkProxy::Raw,
            SockType::SeqPacket => {
                unreachable!("AF_UNIX sockets do not use the network proxy")
            }
            // `SockType` is `#[non_exhaustive]`; all currently declared variants are matched
            // above.
            _ => unreachable!(),
        };
        // Save the proxy in both the descriptor table and the network subsystem so that the shim layer
        // can access it without holding the network lock and the network subsystem can access it without
        // involving the descriptor table (for both performance and convenience).
        let proxy = Arc::new(proxy);
        let old = dt.set_entry_metadata(fd, SocketProxy(proxy.clone()));
        assert!(old.is_none());
        drop(dt);

        if !self.net.lock().set_socket_proxy(fd, proxy.clone()) {
            unreachable!("failed to set socket proxy for a newly-created socket");
        }
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
        match self.setsockopt_common(optname, optval, optlen, |so, value| {
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
                    }
                    (SocketOption::KEEPALIVE, SocketOptionValue::U32(val)) => {
                        let keep_alive = val != 0;
                        deferred_tcp_option = Some(if keep_alive {
                            // default time interval is 2 hours
                            litebox::net::TcpOptionData::KEEPALIVE(Some(
                                core::time::Duration::from_hours(2),
                            ))
                        } else {
                            litebox::net::TcpOptionData::KEEPALIVE(None)
                        });
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
                    // Linux keeps SO_KEEPALIVE as a generic per-socket flag; only TCP's
                    // keepalive timer ever reads it, so UDP/raw sockets accept the call
                    // and it stays inert, same as on real Linux.
                    litebox::net::errors::SetTcpOptionError::NotTcpSocket => {}
                    // `SetTcpOptionError` is `#[non_exhaustive]` but only declares these two
                    // variants, both matched above.
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
                // These IPv4 receive controls are advisory for the in-process stack. The bounded
                // ICMP bridge returns only the echo message, and BusyBox ping does not consume
                // ancillary TTL or returned-option data, so accepting them preserves Linux's
                // socket setup behavior without exposing a raw-packet path.
                litebox_common_linux::IpOption::RETOPTS
                | litebox_common_linux::IpOption::RECVTTL => {
                    let enabled = super::read_from_user::<u32, Platform>(optval, optlen)? != 0;
                    self.with_socket_options_mut(fd, |options| match ip {
                        litebox_common_linux::IpOption::RETOPTS => {
                            options.receive_ipv4_returned_options = enabled;
                        }
                        litebox_common_linux::IpOption::RECVTTL => {
                            options.receive_ipv4_ttl = enabled;
                        }
                        litebox_common_linux::IpOption::TOS => unreachable!(),
                    });
                    return Ok(());
                }
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
                // Credentials passing exists only for AF_UNIX sockets here.
                SocketOption::PASSCRED => {
                    log_unsupported!("setsockopt(SO_PASSCRED) on an inet socket");
                    return Err(Errno::EOPNOTSUPP);
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
                            "reno" | "cubic" => {
                                log_unsupported!("enable {} for smoltcp?", name);
                                return Err(Errno::EINVAL);
                            }
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
                    let val: u32 = super::read_from_user::<_, Platform>(optval, size_of::<u32>())?;
                    // Some applications use Nagle's Algorithm (via the TCP_NODELAY option) for a similar effect.
                    // However, TCP_CORK offers more fine-grained control, as it's designed for applications that
                    // send variable-length chunks of data that don't necessarily fit nicely into a full TCP segment.
                    // Because smoltcp does not support TCP_CORK, we emulate it by enabling/disabling Nagle's Algorithm.
                    let on = if let TcpOption::NODELAY = to {
                        val != 0
                    } else {
                        // CORK is the opposite of NODELAY
                        val == 0
                    };
                    self.net
                        .lock()
                        .set_tcp_option(fd, litebox::net::TcpOptionData::NODELAY(on))?;
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
                            litebox::net::TcpOptionData::KEEPALIVE(Some(
                                core::time::Duration::from_secs(u64::from(val)),
                            )),
                        )
                        .expect("set TCP_KEEPALIVE should succeed");
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
                litebox_common_linux::IpOption::RETOPTS => self
                    .with_socket_options(fd, |options| options.receive_ipv4_returned_options)
                    .into(),
                litebox_common_linux::IpOption::RECVTTL => self
                    .with_socket_options(fd, |options| options.receive_ipv4_ttl)
                    .into(),
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
                SocketOption::PASSCRED => return Err(Errno::EOPNOTSUPP),
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
                            // `CongestionControl` is `#[non_exhaustive]` but only declares these
                            // three variants, all matched above.
                            _ => unreachable!(),
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
                        let TcpOptionData::KEEPALIVE(interval) = self
                            .net
                            .lock()
                            .get_tcp_option(fd, litebox::net::TcpOptionName::KEEPALIVE)?
                        else {
                            unreachable!()
                        };
                        interval.map_or(0, |d| d.as_secs().try_into().unwrap())
                    }
                    TcpOption::NODELAY | TcpOption::CORK => {
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
            AcceptError::InvalidFd | AcceptError::NotListening => TryOpError::Other(e.into()),
            // `AcceptError` is `#[non_exhaustive]` but only declares these three variants, all
            // matched above.
            _ => unreachable!(),
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

    fn icmp_proxy_socket(&self, fd: &SocketFd<Platform>) -> Option<IcmpProxySocket> {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |state: &IcmpProxySocket| *state)
            .ok()
    }

    fn set_icmp_proxy_peer(&self, fd: &SocketFd<Platform>, peer: Ipv4Addr) -> Result<(), Errno> {
        self.litebox
            .descriptor_table_mut()
            .with_metadata_mut(fd, |state: &mut IcmpProxySocket| state.peer = Some(peer))
            .map_err(|err| match err {
                litebox::fd::MetadataError::NoSuchMetadata => Errno::ENOTSOCK,
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })
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
        if self.icmp_proxy_socket(fd).is_some() {
            let SocketAddr::V4(peer) = sockaddr else {
                return Err(Errno::EAFNOSUPPORT);
            };
            if peer.ip().is_unspecified() {
                return Err(Errno::EADDRNOTAVAIL);
            }
            self.set_icmp_proxy_peer(fd, *peer.ip())?;
            self.get_proxy(fd)?.set_state(SocketState::Connected);
            return Ok(());
        }
        if sockaddr.port() == 0 || sockaddr.ip().is_unspecified() {
            return Err(Errno::ECONNREFUSED);
        }
        if let SocketAddr::V4(peer) = sockaddr {
            let ip = *peer.ip();
            let socket_type = self.get_socket_type(fd)?;
            let so_broadcast = self.with_socket_options(fd, |opt| opt.broadcast);
            let net = self.net.lock();
            // Non-unicast destinations. Nothing behind the interface answers a broadcast,
            // multicast or link-local SYN (the platform side forwards unicast only), so the
            // call would sit out the whole connect timeout. Linux refuses these up front:
            // `tcp_v4_connect` reports a broadcast/multicast route as `ENETUNREACH`, and a UDP
            // `connect` to a broadcast address needs `SO_BROADCAST` (`EACCES`); UDP multicast
            // and link-local are allowed and simply go nowhere here.
            let broadcast = ip == Ipv4Addr::BROADCAST || net.is_directed_broadcast(ip);
            if broadcast || ip.is_multicast() || ip.is_link_local() {
                match socket_type {
                    SockType::Stream => return Err(Errno::ENETUNREACH),
                    _ if broadcast && !so_broadcast => return Err(Errno::EACCES),
                    _ => {}
                }
            }
            // Without an external interface (no `utun` on macOS) a SYN to anything but the
            // guest's own addresses is silently dropped, so the connect would only ever end in
            // the caller's timeout. Report the missing route immediately, as Linux does.
            if !net.is_local_ip(ip) && !net.external_interface_available() {
                return Err(Errno::ENETUNREACH);
            }
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
        let guest_len = buf.len();
        let icmp_state = self.icmp_proxy_socket(fd);
        let framed = if let Some(state) = icmp_state {
            const MAX_ICMP_ECHO_SIZE: usize = 4096;
            if !(8..=MAX_ICMP_ECHO_SIZE).contains(&buf.len()) {
                return Err(if buf.len() > MAX_ICMP_ECHO_SIZE {
                    Errno::EMSGSIZE
                } else {
                    Errno::EINVAL
                });
            }
            // Only the bounded unprivileged-ping use case is bridged; this is not a general raw
            // ICMP tunnel.
            if buf[0] != 8 || buf[1] != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            let target = match sockaddr {
                Some(SocketAddr::V4(target)) => *target.ip(),
                Some(SocketAddr::V6(_)) => return Err(Errno::EAFNOSUPPORT),
                None => state.peer.ok_or(Errno::EDESTADDRREQ)?,
            };
            if target.is_unspecified() || target.is_multicast() || target == Ipv4Addr::BROADCAST {
                return Err(Errno::EINVAL);
            }
            let mut frame = alloc::vec::Vec::with_capacity(
                litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN + buf.len(),
            );
            frame.extend_from_slice(&target.octets());
            frame.extend_from_slice(buf);
            Some(frame)
        } else {
            None
        };
        let wire_buf = framed.as_deref().unwrap_or(buf);
        let wire_sockaddr = if framed.is_some() {
            Some(SocketAddr::V4(litebox::net::ICMP_ECHO_PROXY_ADDR))
        } else {
            sockaddr
        };
        let proxy = self.get_proxy(fd)?;

        // A datagram to a broadcast address needs `SO_BROADCAST`, as on Linux (`EACCES`).
        if let (NetworkProxy::Datagram(_), Some(SocketAddr::V4(dest))) =
            (proxy.as_ref(), wire_sockaddr)
        {
            let ip = *dest.ip();
            if ip.octets()[3] == 255
                && (ip == Ipv4Addr::BROADCAST || self.net.lock().is_directed_broadcast(ip))
                && !self.with_socket_options(fd, |opt| opt.broadcast)
            {
                return Err(Errno::EACCES);
            }
        }

        // Auto-bind UDP sockets if not already bound (Linux behavior: sendto() on an unbound
        // UDP socket implicitly binds it to an ephemeral port before sending).
        // This is mostly lock-free: we only take the network lock if we need to allocate a port.
        if let NetworkProxy::Datagram(proxy) = proxy.as_ref()
            && proxy.local_port() == 0
        {
            // UDP socket is unbound - bind to an ephemeral port
            let mut net = self.net.lock();
            // Bind with port 0 to get an ephemeral port
            if let Err(err) = net.bind(
                fd,
                &SocketAddr::V4(core::net::SocketAddrV4::new(
                    core::net::Ipv4Addr::UNSPECIFIED,
                    0,
                )),
            ) {
                match err {
                    litebox::net::errors::BindError::AlreadyBound => {
                        // Another thread bound it in the meantime - that's fine
                    }
                    litebox::net::errors::BindError::InvalidFd => return Err(Errno::EBADF),
                    // `BindError` is `#[non_exhaustive]` but only declares these four variants,
                    // all matched here or above; `_` covers the same two named on the left.
                    litebox::net::errors::BindError::UnsupportedAddress(_)
                    | litebox::net::errors::BindError::PortAlreadyInUse(_)
                    | _ => unreachable!(),
                }
            }
            // Get the assigned port
            let local_addr = net.get_local_addr(fd).map_err(Errno::from)?;
            // If another thread already set a port, that's fine - we'll use theirs
            let _ = proxy.set_local_port(local_addr.port());
        }

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
        let is_stream = matches!(proxy.as_ref(), NetworkProxy::Stream(_));
        let is_empty_stream = guest_len == 0 && is_stream;

        // A blocking stream send returns only once every byte is queued (Linux `tcp_sendmsg`
        // loops, sleeping on send space): a short count comes back only when `SO_SNDTIMEO`
        // or a signal cuts the wait after some bytes went in. Non-blocking and datagram sends
        // are a single attempt.
        let mut written = 0usize;
        loop {
            let chunk = &wire_buf[written..];
            let attempt = cx.with_timeout(timeout).wait_on_events(
                is_nonblock,
                Events::OUT,
                |observer, filter| {
                    proxy.register_observer(observer, filter);
                    Ok(())
                },
                || match proxy.try_write(chunk, new_flags, wire_sockaddr) {
                    Ok(n) if framed.is_some() && n == chunk.len() => Ok(guest_len),
                    Ok(_) if framed.is_some() => Err(TryOpError::Other(Errno::EIO)),
                    Ok(0) if guest_len == 0 => Ok(0),
                    Ok(0) => Err(TryOpError::TryAgain),
                    Ok(n) => Ok(n),
                    Err(ChannelWriteError::BufferFull) if is_empty_stream => Ok(0),
                    // No room in the socket's send buffer: a blocking send waits for the
                    // network worker to drain it (bounded by `SO_SNDTIMEO`); only `O_NONBLOCK`
                    // / `MSG_DONTWAIT` turn this into `EAGAIN`, as on Linux.
                    Err(ChannelWriteError::BufferFull) => Err(TryOpError::TryAgain),
                    Err(e) => Err(TryOpError::Other(Errno::from(e))),
                },
            );
            match attempt {
                Ok(n) => {
                    written += n;
                    if written >= wire_buf.len() || is_nonblock || !is_stream || framed.is_some() {
                        return Ok(written);
                    }
                }
                Err(_) if written > 0 => return Ok(written),
                // `SO_SNDTIMEO` ran out with nothing sent: Linux reports `EAGAIN`
                // (`sk_stream_wait_memory`), keeping `ETIMEDOUT` for the connection itself.
                Err(TryOpError::WaitError(WaitError::TimedOut)) => return Err(Errno::EAGAIN),
                Err(e) => return Err(Errno::from(e)),
            }
        }
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
        mut source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, Errno> {
        let timeout = self.with_socket_options(fd, |opt| opt.recv_timeout);
        let is_nonblock = self.get_status(fd).contains(OFlags::NONBLOCK)
            || flags.contains(ReceiveFlags::DONTWAIT);

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
        // `MSG_TRUNC` behavior depends on the socket type
        if flags.contains(ReceiveFlags::TRUNC) {
            match self.get_socket_type(fd)? {
                SockType::Datagram | SockType::Raw | SockType::SeqPacket => {
                    new_flags.insert(litebox::net::ReceiveFlags::TRUNC);
                }
                SockType::Stream => {
                    new_flags.insert(litebox::net::ReceiveFlags::DISCARD);
                }
                // `SockType` is `#[non_exhaustive]`; all currently declared variants are matched
                // above.
                _ => unreachable!(),
            }
        }

        let proxy = self.get_proxy(fd)?;
        if self.icmp_proxy_socket(fd).is_some() {
            let frame_len = buf
                .len()
                .checked_add(litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN)
                .ok_or(Errno::EINVAL)?;
            let mut frame = alloc::vec![0u8; frame_len];
            return cx
                .with_timeout(timeout)
                .wait_on_events(
                    is_nonblock,
                    Events::IN,
                    |observer, filter| {
                        proxy.register_observer(observer, filter);
                        Ok(())
                    },
                    || match proxy.try_read(&mut frame, new_flags, None) {
                        Ok(n) if n < litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN => {
                            Err(TryOpError::TryAgain)
                        }
                        Ok(n) => {
                            let payload_len = n - litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN;
                            let available =
                                n.min(frame.len()) - litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN;
                            let copied = available.min(buf.len());
                            buf[..copied].copy_from_slice(
                                &frame[litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN
                                    ..litebox::net::ICMP_ECHO_PROXY_PREFIX_LEN + copied],
                            );
                            if let Some(source_addr) = source_addr.as_deref_mut() {
                                *source_addr = Some(SocketAddr::V4(SocketAddrV4::new(
                                    Ipv4Addr::new(frame[0], frame[1], frame[2], frame[3]),
                                    0,
                                )));
                            }
                            Ok(if flags.contains(ReceiveFlags::TRUNC) {
                                payload_len
                            } else {
                                copied
                            })
                        }
                        Err(ChannelReadError::ReadShutdown) => Ok(0),
                        Err(ChannelReadError::ConnectionClosed) => {
                            match proxy.get_async_error(true) {
                                Some(err) => Err(TryOpError::Other(err.into())),
                                None => Ok(0),
                            }
                        }
                        Err(ChannelReadError::NotConnected) => {
                            Err(TryOpError::Other(Errno::ENOTCONN))
                        }
                    },
                )
                .map_err(Errno::from);
        }
        cx.with_timeout(timeout)
            .wait_on_events(
                is_nonblock,
                Events::IN,
                |observer, filter| {
                    proxy.register_observer(observer, filter);
                    Ok(())
                },
                || match proxy.try_read(buf, new_flags, source_addr.as_deref_mut()) {
                    Ok(0) => Err(TryOpError::TryAgain),
                    Ok(n) => Ok(n),
                    Err(ChannelReadError::ReadShutdown) => Ok(0),
                    Err(ChannelReadError::ConnectionClosed) => match proxy.get_async_error(true) {
                        Some(err) => Err(TryOpError::Other(err.into())),
                        None => Ok(0),
                    },
                    Err(ChannelReadError::NotConnected) => Err(TryOpError::Other(Errno::ENOTCONN)),
                },
            )
            .map_err(|err| match err {
                // `SO_RCVTIMEO` ran out: Linux reports `EAGAIN` (`sock_rcvtimeo`), not `ETIMEDOUT`.
                TryOpError::WaitError(WaitError::TimedOut) => Errno::EAGAIN,
                err => Errno::from(err),
            })
    }

    fn get_socket_type(&self, fd: &SocketFd<Platform>) -> Result<SockType, Errno> {
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
            || match self.net.lock().close(&fd, behavior) {
                Ok(()) => Ok(()),
                Err(litebox::net::errors::CloseError::DataPending) => Err(TryOpError::TryAgain),
                Err(litebox::net::errors::CloseError::InvalidFd) => {
                    Err(TryOpError::Other(Errno::EBADF))
                }
                // `CloseError` is `#[non_exhaustive]` but only declares these two variants, both
                // matched above.
                Err(_) => unreachable!(),
            },
        ) {
            Ok(()) => Ok(()),
            Err(TryOpError::WaitError(WaitError::TimedOut)) => self
                .net
                .lock()
                .close(&fd, CloseBehavior::Immediate)
                .map_err(Errno::from),
            Err(e) => Err(e.into()),
        }
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
                let mut icmp_proxy = false;
                let protocol = match ty {
                    SockType::Stream => {
                        if !matches!(protocol, IPProtocol::Default | IPProtocol::TCP) {
                            return Err(Errno::EINVAL);
                        }
                        litebox::net::Protocol::Tcp
                    }
                    SockType::Datagram => match protocol {
                        IPProtocol::Default | IPProtocol::UDP => litebox::net::Protocol::Udp,
                        IPProtocol::ICMP => {
                            icmp_proxy = true;
                            litebox::net::Protocol::Udp
                        }
                        IPProtocol::TCP | IPProtocol::RAW => return Err(Errno::EINVAL),
                        // `IPProtocol` is non-exhaustive; `try_from` admitted only a declared value.
                        _ => unreachable!(),
                    },
                    // No raw IP networking of any kind is available: the host has no `tun`
                    // device without root (see `net_proxy`'s module doc), so there is no path
                    // to actually emit an ICMP echo or any other raw packet. `EPERM` matches
                    // what an unprivileged Linux process making this same call without
                    // `CAP_NET_RAW` sees, so `ping`'s own "Operation not permitted" is exactly
                    // what a caller would expect in a sandboxed environment -- a clean syscall
                    // failure instead of a guest-crashing panic.
                    SockType::Raw => return Err(Errno::EPERM),
                    SockType::SeqPacket => return Err(Errno::ESOCKTNOSUPPORT),
                    // `SockType` is `#[non_exhaustive]`; all currently declared variants are
                    // matched above.
                    _ => unreachable!(),
                };
                let socket = self.global.net.lock().socket(protocol)?;
                let _ = self.global.initialize_socket(&socket, ty, flags);
                if icmp_proxy {
                    let old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_entry_metadata(&socket, IcmpProxySocket::default());
                    assert!(old.is_none());
                }
                let Ok(raw_fd) = files.insert_raw_fd(socket) else {
                    unimplemented!()
                };
                raw_fd
            }
            AddressFamily::UNIX => {
                let _ = UnixProtocol::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
                let socket = UnixSocket::new(ty, flags, self).ok_or(Errno::ESOCKTNOSUPPORT)?;
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
            AddressFamily::NETLINK => {
                // A `NETLINK_ROUTE` socket, just enough for `getifaddrs(3)` /
                // `os.networkInterfaces()`. `ty` (SOCK_RAW/SOCK_DGRAM) and `protocol`
                // (NETLINK_ROUTE) are accepted without distinction -- no real link or
                // address state is ever touched; see `crate::syscalls::netlink`.
                let (interface_ip, gateway_ip) = {
                    let net = self.global.net.lock();
                    (net.interface_ip(), net.gateway_ip())
                };
                let socket = crate::syscalls::netlink::NetlinkSocket::new(interface_ip, gateway_ip);
                let mut status = OFlags::RDWR;
                status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                let mut descriptors = self.global.litebox.descriptor_table_mut();
                let typed = descriptors
                    .insert::<crate::syscalls::netlink::NetlinkSubsystem<Platform>>(socket);
                let old = descriptors.set_entry_metadata(&typed, SocketOFlags(status));
                assert!(old.is_none());
                if flags.contains(SockFlags::CLOEXEC) {
                    let old = descriptors.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }
                drop(descriptors);
                files.insert_raw_fd(typed).map_err(|typed| {
                    let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                    Errno::EMFILE
                })?
            }
            AddressFamily::INET6 => return Err(Errno::EAFNOSUPPORT),
            // `AddressFamily` is `#[non_exhaustive]` but only declares these four variants, all
            // matched above; `domain` only reaches here via `AddressFamily::try_from`, which
            // rejects anything else before construction.
            _ => unreachable!(),
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
                let (sock1, sock2) = UnixSocket::new_connected_pair(ty, flags, self)
                    .ok_or(Errno::ESOCKTNOSUPPORT)?;
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
            // The kernel bounds the pathname by `addrlen` with the NUL optional
            // (`unix(7)`: "the terminating null byte is not required"); dbus and X both
            // pass exactly `offsetof(sun_path) + strlen(path)`. Requiring an embedded NUL
            // here rejected every such bind with EINVAL.
            let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            Ok(SocketAddress::Unix(UnixSocketAddr::Path(
                alloc::string::String::from_utf8_lossy(&path[..end]).to_string(),
            )))
        }
        // Unlike `do_socket`'s `AddressFamily` match, `INET6`/`NETLINK` really are reachable
        // here: this parses a sockaddr the guest supplies as a syscall argument (e.g. to
        // `connect`/`bind`), which is independent of whatever family the fd itself was created
        // with, so a mismatched or IPv6 sockaddr is a real, guest-triggerable input rather than
        // exhaustiveness padding. Report it the same way `do_socket` reports an unsupported
        // socket domain instead of aborting on it.
        _ => Err(Errno::EAFNOSUPPORT),
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
        SocketAddress::Inet(SocketAddr::V6(v6_addr)) => {
            let addrlen_val = size_of::<CSockInet6Addr>().min(addrlen_val as usize);
            let c_addr: CSockInet6Addr = v6_addr.into();
            let bytes: &[u8] = c_addr.as_bytes();
            addr.write_slice_at_offset::<Platform>(0, &bytes[..addrlen_val])
                .ok_or(Errno::EFAULT)?;
            size_of::<CSockInet6Addr>()
        }
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
                let Ok(raw_fd) = files.insert_raw_fd(accepted_file) else {
                    unimplemented!()
                };
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
        // A `NETLINK_ROUTE` socket is bound to a `sockaddr_nl`, not the inet/unix
        // address `read_sockaddr_from_user` understands -- so resolve it before
        // parsing the address (which would otherwise reject AF_NETLINK). Accept it
        // as a no-op: there is no per-socket netlink group state to register.
        if self.netlink_fd(sockfd).is_some() {
            return Ok(());
        }
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

    /// If `sockfd` is a `NETLINK_ROUTE` socket, return its typed fd; otherwise
    /// `None` (a non-netlink or absent fd falls through to the normal socket path).
    fn netlink_fd(
        &self,
        sockfd: u32,
    ) -> Option<
        alloc::sync::Arc<
            litebox::fd::TypedFd<crate::syscalls::netlink::NetlinkSubsystem<Platform>>,
        >,
    > {
        self.files
            .borrow()
            .raw_descriptor_store
            .read()
            .fd_from_raw_integer::<crate::syscalls::netlink::NetlinkSubsystem<Platform>>(
                sockfd as usize,
            )
            .ok()
    }

    /// `send`/`sendto`/`write` on a netlink socket: enqueue the dump the matching
    /// reads will drain. `Some` iff `sockfd` is a netlink socket.
    pub(crate) fn netlink_send(&self, sockfd: u32, buf: &[u8]) -> Option<Result<usize, Errno>> {
        let nl = self.netlink_fd(sockfd)?;
        Some(
            self.global
                .litebox
                .descriptor_table()
                .with_entry(&nl, |sock| sock.handle_send(buf))
                .ok_or(Errno::EBADF),
        )
    }

    /// `recv`/`recvfrom`/`read` on a netlink socket: drain pending dump bytes.
    /// `Some` iff `sockfd` is a netlink socket.
    pub(crate) fn netlink_recv(&self, sockfd: u32, buf: &mut [u8]) -> Option<Result<usize, Errno>> {
        let nl = self.netlink_fd(sockfd)?;
        Some(
            self.global
                .litebox
                .descriptor_table()
                .with_entry(&nl, |sock| sock.handle_recv(buf))
                .unwrap_or(Err(Errno::EBADF)),
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
            |file| file.listen(backlog, &self.global, self),
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
        if let Some(res) = self.netlink_send(sockfd, buf) {
            return res;
        }
        let res = self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
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
        // A netlink socket takes `sendmsg` exactly like `sendto`: iproute2/busybox `ip`'s
        // `rtnl_talk` (`ip route get`) sends with a `sockaddr_nl` name, which the inet
        // address parse below rejects as `EAFNOSUPPORT`, so it is answered first.
        if self.netlink_fd(sockfd).is_some() {
            let data = if msg.msg_iovlen == 0 {
                alloc::vec::Vec::new()
            } else {
                let iovs = msg
                    .msg_iov
                    .to_owned_slice::<Platform>(msg.msg_iovlen)
                    .ok_or(Errno::EFAULT)?;
                copy_iovs_to_vec::<Platform>(&iovs)?
            };
            return self
                .netlink_send(sockfd, &data)
                .unwrap_or(Err(Errno::EBADF));
        }
        let msg_name = msg.msg_name;
        let sock_addr = if msg_name.as_usize() != 0 {
            Some(read_sockaddr_from_user::<Platform>(
                UserPtr::from_usize(msg_name.as_usize()),
                msg.msg_namelen as usize,
            )?)
        } else {
            None
        };
        let msg_control = msg.msg_control;
        let msg_controllen = msg.msg_controllen;
        let mut rights = alloc::vec::Vec::new();
        // An explicit `SCM_CREDENTIALS` the sender attached (at most one), validated below
        // the way Linux's `scm_check_creds` does: an unprivileged sender may only claim its
        // own process id and one of its real/effective/saved ids.
        let mut credentials: Option<litebox_common_linux::Ucred> = None;
        if msg_controllen != 0 {
            const SOL_SOCKET: u32 = 1;
            const SCM_RIGHTS: u32 = 1;
            const SCM_CREDENTIALS: u32 = 2;
            const SCM_MAX_FD: usize = 253;
            const CMSG_HEADER_LEN: usize = size_of::<usize>() + 2 * size_of::<u32>();

            let control = msg_control
                .to_owned_slice::<Platform>(msg_controllen)
                .ok_or(Errno::EFAULT)?;
            let read_usize = |bytes: &[u8], offset: usize| -> Result<usize, Errno> {
                let end = offset
                    .checked_add(size_of::<usize>())
                    .ok_or(Errno::EINVAL)?;
                let bytes: [u8; size_of::<usize>()] = bytes
                    .get(offset..end)
                    .ok_or(Errno::EINVAL)?
                    .try_into()
                    .map_err(|_| Errno::EINVAL)?;
                Ok(usize::from_ne_bytes(bytes))
            };
            let read_u32 = |bytes: &[u8], offset: usize| -> Result<u32, Errno> {
                let end = offset.checked_add(size_of::<u32>()).ok_or(Errno::EINVAL)?;
                let bytes: [u8; size_of::<u32>()] = bytes
                    .get(offset..end)
                    .ok_or(Errno::EINVAL)?
                    .try_into()
                    .map_err(|_| Errno::EINVAL)?;
                Ok(u32::from_ne_bytes(bytes))
            };

            let mut offset = 0usize;
            while offset < control.len() {
                let remaining = control.len() - offset;
                if remaining < CMSG_HEADER_LEN {
                    return Err(Errno::EINVAL);
                }
                let cmsg_len = read_usize(&control, offset)?;
                if !(CMSG_HEADER_LEN..=remaining).contains(&cmsg_len) {
                    return Err(Errno::EINVAL);
                }
                let level_offset = offset + size_of::<usize>();
                let type_offset = level_offset + size_of::<u32>();
                let cmsg_level = read_u32(&control, level_offset)?;
                let cmsg_type = read_u32(&control, type_offset)?;
                let data = &control[offset + CMSG_HEADER_LEN..offset + cmsg_len];

                match (cmsg_level, cmsg_type) {
                    (SOL_SOCKET, SCM_RIGHTS) => {
                        if data.is_empty() || data.len() % size_of::<i32>() != 0 {
                            return Err(Errno::EINVAL);
                        }
                        let count = data.len() / size_of::<i32>();
                        if rights.len().checked_add(count).ok_or(Errno::EINVAL)? > SCM_MAX_FD {
                            return Err(Errno::EINVAL);
                        }
                        // Exact by the length check above, so the remainder is empty.
                        let (fds, _) = data.as_chunks::<{ size_of::<i32>() }>();
                        for raw_fd in fds {
                            let raw_fd = i32::from_ne_bytes(*raw_fd);
                            rights.push(self.transfer_fd(raw_fd)?);
                        }
                    }
                    (SOL_SOCKET, SCM_CREDENTIALS) => {
                        if credentials.is_some()
                            || data.len() != size_of::<litebox_common_linux::Ucred>()
                        {
                            return Err(Errno::EINVAL);
                        }
                        let supplied = litebox_common_linux::Ucred {
                            pid: read_u32(data, 0)?,
                            uid: read_u32(data, size_of::<u32>())?,
                            gid: read_u32(data, 2 * size_of::<u32>())?,
                        };
                        let own = self.credentials.borrow();
                        let uid_ok = [own.uid, own.euid, own.suid].contains(&supplied.uid);
                        let gid_ok = [own.gid, own.egid, own.sgid].contains(&supplied.gid);
                        if supplied.pid != self.pid.cast_unsigned() || !uid_ok || !gid_ok {
                            return Err(Errno::EPERM);
                        }
                        credentials = Some(supplied);
                    }
                    _ => return Err(Errno::EINVAL),
                }

                let aligned = cmsg_len
                    .checked_add(size_of::<usize>() - 1)
                    .ok_or(Errno::EINVAL)?
                    & !(size_of::<usize>() - 1);
                if aligned >= remaining {
                    break;
                }
                offset = offset.checked_add(aligned).ok_or(Errno::EINVAL)?;
            }
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
        let rights = core::cell::RefCell::new(Some(rights));
        let res = self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                if credentials.is_some() || !rights.borrow().as_ref().unwrap().is_empty() {
                    return Err(Errno::EINVAL);
                }
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
                file.sendmsg(
                    self,
                    &data,
                    flags,
                    unix_addr,
                    rights.borrow_mut().take().unwrap(),
                    credentials,
                )
            },
        );
        if let Err(Errno::EPIPE) = res
            && !flags.contains(SendFlags::NOSIGNAL)
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
        const MAX_LEN: usize = 4096;
        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let mut source_addr = None;
        let mut buffer = [0u8; MAX_LEN];
        let recv_buf = &mut buffer[..MAX_LEN.min(len)];
        let size = self.do_recvfrom(
            sockfd,
            recv_buf,
            flags,
            if addr.is_some() {
                Some(&mut source_addr)
            } else {
                None
            },
        )?;
        let capped_size = size.min(recv_buf.len());
        buf.copy_from_slice::<Platform>(0, &recv_buf[..capped_size])
            .ok_or(Errno::EFAULT)?;
        if let Some(src_addr) = source_addr
            && let Some(sock_ptr) = addr
        {
            write_sockaddr_to_user::<Platform>(src_addr, sock_ptr, addrlen)?;
        }

        if flags.contains(ReceiveFlags::TRUNC) {
            // the actual message size
            Ok(size)
        } else {
            // the number of bytes copied
            Ok(capped_size)
        }
    }
    /// Receive data from a socket.
    ///
    /// `source_addr` can be provided to receive the source address if available.
    ///
    /// On success, returns the number of bytes received. Note that for datagram sockets,
    /// this may be larger than the provided buffer length as the excessive data will be truncated.
    fn do_recvfrom(
        &self,
        sockfd: u32,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        self.do_recvfrom_with_rights(sockfd, buf, flags, source_addr)
            .map(|received| received.size)
    }

    /// Receives into `buf` together with the ancillary payload a `recvmsg` would deliver:
    /// the transferred descriptors (`SCM_RIGHTS`) and, when the receiving `AF_UNIX` socket
    /// has `SO_PASSCRED` set, the sender's `SCM_CREDENTIALS`.
    fn do_recvfrom_with_rights(
        &self,
        sockfd: u32,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<Received<Platform, FS>, Errno> {
        if let Some(res) = self.netlink_recv(sockfd, buf) {
            return res.map(|size| Received {
                size,
                rights: alloc::vec::Vec::new(),
                credentials: None,
            });
        }
        let want_source = source_addr.is_some();
        let files = self.files.borrow();
        let raw_fd = usize::try_from(sockfd).or(Err(Errno::EBADF))?;
        let (received, addr) = {
            // We need to do this cell dance because otherwise Rust can't recognize that the two
            // closures are mutually exclusive.
            let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
            files.with_socket(
                &self.global,
                raw_fd.trunc(),
                |fd| {
                    let mut addr = None;
                    let size = self.global.receive(
                        &self.wait_cx(),
                        fd,
                        &mut buf.borrow_mut(),
                        flags,
                        if want_source { Some(&mut addr) } else { None },
                    )?;
                    let src_addr = addr.map(SocketAddress::Inet);
                    Ok((
                        Received {
                            size,
                            rights: alloc::vec::Vec::new(),
                            credentials: None,
                        },
                        src_addr,
                    ))
                },
                |entry| {
                    let mut addr = None;
                    let result = entry.recvmsg(
                        &self.wait_cx(),
                        &mut buf.borrow_mut(),
                        flags,
                        if want_source { Some(&mut addr) } else { None },
                    )?;
                    let src_addr = addr.map(SocketAddress::Unix);
                    Ok((
                        Received {
                            size: result.size,
                            rights: result.rights,
                            credentials: result.credentials,
                        },
                        src_addr,
                    ))
                },
            )?
        };

        if let (Some(source_addr), Some(addr)) = (source_addr, addr) {
            *source_addr = Some(addr);
        }
        Ok(received)
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

        let supported_flags =
            ReceiveFlags::DONTWAIT | ReceiveFlags::TRUNC | ReceiveFlags::CMSG_CLOEXEC;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvmsg flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }

        self.do_recvmsg(sockfd, msg_ptr, flags)
    }
    fn do_recvmsg(
        &self,
        sockfd: u32,
        msg_ptr: UserPtrMut<litebox_common_linux::UserMsgHdr>,
        flags: ReceiveFlags,
    ) -> Result<usize, Errno> {
        const SOL_SOCKET: u32 = 1;
        const SCM_RIGHTS: u32 = 1;
        const SCM_CREDENTIALS: u32 = 2;
        const CMSG_HEADER_LEN: usize = size_of::<usize>() + 2 * size_of::<u32>();

        let msg = msg_ptr.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;

        // Copy fields out of the packed struct to avoid unaligned references.
        let msg_name = msg.msg_name;
        let msg_iov = msg.msg_iov;
        let msg_iovlen = msg.msg_iovlen;
        let msg_control = msg.msg_control;
        let msg_controllen = msg.msg_controllen;

        if msg_iovlen > UIO_MAXIOV {
            return Err(Errno::EMSGSIZE);
        }

        let iovs = msg_iov
            .to_owned_slice::<Platform>(msg_iovlen)
            .ok_or(Errno::EFAULT)?;

        let total_iov_capacity = iovs.iter().try_fold(0usize, |capacity, iov| {
            capacity.checked_add(iov.iov_len).ok_or(Errno::EINVAL)
        })?;

        // Perform a single recv into a contiguous buffer.
        let want_source = msg_name.as_usize() != 0;
        let mut source_addr = None;
        let mut ret_flags = ReceiveFlags::empty();

        // Heap-allocate the recv buffer to avoid stack overflow for large iovecs.
        let mut buffer = alloc::vec::Vec::new();
        buffer
            .try_reserve_exact(total_iov_capacity)
            .map_err(|_| Errno::ENOMEM)?;
        buffer.resize(total_iov_capacity, 0);
        let recv_buf = &mut buffer[..];
        let Received {
            size,
            rights,
            credentials,
        } = self.do_recvfrom_with_rights(
            sockfd,
            recv_buf,
            flags.difference(ReceiveFlags::CMSG_CLOEXEC),
            if want_source {
                Some(&mut source_addr)
            } else {
                None
            },
        )?;

        if size > total_iov_capacity {
            ret_flags.insert(ReceiveFlags::TRUNC);
        }

        // Scatter the received data across iovecs sequentially.
        let data_to_copy = size.min(total_iov_capacity);
        let mut offset = 0usize;
        for iov in &iovs {
            if offset >= data_to_copy {
                break;
            }
            if iov.iov_len == 0 {
                continue;
            }
            let chunk = (data_to_copy - offset).min(iov.iov_len);
            iov.iov_base
                .copy_from_slice::<Platform>(0, &recv_buf[offset..offset + chunk])
                .ok_or(Errno::EFAULT)?;
            offset += chunk;
        }

        let total_received = if flags.contains(ReceiveFlags::TRUNC) {
            // the actual message size
            size
        } else {
            // the number of bytes copied
            size.min(total_iov_capacity)
        };

        // Write back source address if requested.
        if want_source {
            let addrlen_ptr = UserPtrMut::<u32>::from_usize(
                msg_ptr.as_usize()
                    + core::mem::offset_of!(litebox_common_linux::UserMsgHdr, msg_namelen),
            );
            if self.netlink_fd(sockfd).is_some() {
                // A `recvmsg` on a netlink socket reports a `sockaddr_nl` source:
                // `{ u16 nl_family = AF_NETLINK, u16 pad, u32 nl_pid = 0 (from the
                // kernel), u32 nl_groups = 0 }`. iproute2/busybox `ip` reject a
                // reply whose sender length isn't `sizeof(sockaddr_nl)` or whose
                // `nl_pid` is nonzero, so this must be present and zero-pid.
                let mut nl = [0u8; 12];
                nl[0..2].copy_from_slice(&(AddressFamily::NETLINK as u16).to_ne_bytes());
                let cap = msg.msg_namelen as usize;
                let n = nl.len().min(cap);
                msg_name
                    .write_slice_at_offset::<Platform>(0, &nl[..n])
                    .ok_or(Errno::EFAULT)?;
                // `sizeof(struct sockaddr_nl)` == 12.
                addrlen_ptr
                    .write_at_offset::<Platform>(0, 12u32)
                    .ok_or(Errno::EFAULT)?;
            } else if let Some(src_addr) = source_addr {
                write_sockaddr_to_user::<Platform>(src_addr, msg_name, addrlen_ptr)?;
            } else {
                // No source address (e.g. connected stream socket) — zero out msg_namelen.
                addrlen_ptr
                    .write_at_offset::<Platform>(0, 0u32)
                    .ok_or(Errno::EFAULT)?;
            }
        }

        // Ancillary data, in the order Linux's `scm_recv` emits it: SCM_CREDENTIALS (only
        // when the receiving socket has SO_PASSCRED) first, then SCM_RIGHTS. Each control
        // message consumes CMSG_SPACE of the caller's buffer; whatever no longer fits is
        // truncated (descriptors that don't fit are closed, not installed) and reported
        // through MSG_CTRUNC. A null control pointer offers no space at all.
        let control_capacity = if msg_control.as_usize() == 0 {
            0
        } else {
            msg_controllen
        };
        let mut control = alloc::vec::Vec::new();
        if let Some(ucred) = credentials {
            let mut payload = [0u8; 3 * size_of::<u32>()];
            payload[..4].copy_from_slice(&ucred.pid.to_ne_bytes());
            payload[4..8].copy_from_slice(&ucred.uid.to_ne_bytes());
            payload[8..].copy_from_slice(&ucred.gid.to_ne_bytes());
            litebox_util_log::trace!(
                sockfd,
                sender_pid = ucred.pid,
                sender_uid = ucred.uid,
                sender_gid = ucred.gid,
                control_capacity;
                "recvmsg: delivering SCM_CREDENTIALS"
            );
            if put_cmsg(
                &mut control,
                control_capacity,
                SOL_SOCKET,
                SCM_CREDENTIALS,
                &payload,
            ) {
                ret_flags.insert(ReceiveFlags::CTRUNC);
            }
        }

        let rights_count = rights.len();
        let max_control_fds = control_capacity
            .saturating_sub(control.len())
            .checked_sub(CMSG_HEADER_LEN)
            .map_or(0, |space| space / size_of::<i32>());
        let cloexec = flags.contains(ReceiveFlags::CMSG_CLOEXEC);
        let mut installed: alloc::vec::Vec<(usize, i32)> = alloc::vec::Vec::new();
        for transferred in rights.into_iter().take(max_control_fds) {
            match self.install_transferred_fd(transferred, cloexec) {
                Ok(raw_fd) => {
                    let Ok(guest_fd) = i32::try_from(raw_fd) else {
                        let _ = self.do_close(raw_fd);
                        break;
                    };
                    installed.push((raw_fd, guest_fd));
                }
                Err(Errno::EMFILE) => break,
                Err(error) => {
                    for (raw_fd, _) in installed.drain(..) {
                        let _ = self.do_close(raw_fd);
                    }
                    return Err(error);
                }
            }
        }
        if installed.len() < rights_count {
            ret_flags.insert(ReceiveFlags::CTRUNC);
        }
        if !installed.is_empty() {
            let mut payload = alloc::vec::Vec::with_capacity(installed.len() * size_of::<i32>());
            for (_, guest_fd) in &installed {
                payload.extend_from_slice(&guest_fd.to_ne_bytes());
            }
            if put_cmsg(
                &mut control,
                control_capacity,
                SOL_SOCKET,
                SCM_RIGHTS,
                &payload,
            ) {
                ret_flags.insert(ReceiveFlags::CTRUNC);
            }
        }

        let control_len = control.len();
        if control_len != 0 {
            let control_ptr = UserPtrMut::<u8>::from_usize(msg_control.as_usize());
            if control_ptr
                .write_slice_at_offset::<Platform>(0, &control)
                .is_none()
            {
                for (raw_fd, _) in installed.drain(..) {
                    let _ = self.do_close(raw_fd);
                }
                return Err(Errno::EFAULT);
            }
        }

        let controllen_offset =
            core::mem::offset_of!(litebox_common_linux::UserMsgHdr, msg_controllen);
        let controllen_ptr =
            UserPtrMut::<usize>::from_usize(msg_ptr.as_usize() + controllen_offset);
        let flags_offset = core::mem::offset_of!(litebox_common_linux::UserMsgHdr, msg_flags);
        let flags_ptr = UserPtrMut::<ReceiveFlags>::from_usize(msg_ptr.as_usize() + flags_offset);
        let metadata_result = controllen_ptr
            .write_at_offset::<Platform>(0, control_len)
            .ok_or(Errno::EFAULT)
            .and_then(|()| {
                flags_ptr
                    .write_at_offset::<Platform>(0, ret_flags)
                    .ok_or(Errno::EFAULT)
            });
        if let Err(error) = metadata_result {
            for (raw_fd, _) in installed {
                let _ = self.do_close(raw_fd);
            }
            return Err(error);
        }

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
            | ReceiveFlags::TRUNC
            | ReceiveFlags::WAITFORONE
            | ReceiveFlags::CMSG_CLOEXEC;
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
        let inet_proxy = self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| self.global.get_proxy(fd).map(Some),
            |_| Ok(None),
        )?;

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

        // WAITFORONE is mmsg-only; the inner recvmsg doesn't recognize it.
        let waitforone = flags.contains(ReceiveFlags::WAITFORONE);
        let mut iter_flags = flags.difference(ReceiveFlags::WAITFORONE);
        let mut received: usize = 0;
        let mut last_err: Option<Errno> = None;
        let mut async_error_to_restore = None;
        for i in 0..vlen {
            let base = msgvec_base + i * stride;
            let inner_ptr = UserPtrMut::<UserMsgHdr>::from_usize(base);
            let n = match self.do_recvmsg(sockfd, inner_ptr, iter_flags) {
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
        if let (Some(async_error), Some(proxy)) = (async_error_to_restore, inet_proxy) {
            proxy.set_async_error(async_error);
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
            log_unsupported!("getsockopt(level = {level}, optname = {optname})");
            Errno::ENOPROTOOPT
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
                self.global
                    .net
                    .lock()
                    .shutdown(fd, how.is_shutdown_read(), how.is_shutdown_write())
                    .map_err(|err| match err {
                        litebox::net::ShutdownError::InvalidFd => Errno::EBADF,
                        litebox::net::ShutdownError::NotConnected => Errno::ENOTCONN,
                        // `ShutdownError` is `#[non_exhaustive]`; both declared variants are
                        // matched above.
                        _ => Errno::EINVAL,
                    })
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
        AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption,
        SocketOptionName, TcpOption, errno::Errno,
    };
    use zerocopy::FromZeros as _;

    use super::SocketAddress;
    use crate::{
        UserPtr, UserPtrMut,
        syscalls::{
            net::{CSockInet6Addr, CSockInetAddr, read_sockaddr_from_user, write_sockaddr_to_user},
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

    const TUN_IP_ADDR: [u8; 4] = [10, 0, 0, 2];
    const TUN_IP_ADDR_STR: &str = "10.0.0.2";
    const TUN_DEVICE_NAME: &str = "tun99";
    const SERVER_PORT: u16 = 8080;
    const CLIENT_PORT: u16 = 8081;

    fn close_socket(task: &TestTask, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
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
            match option {
                "sendto" | "sendmsg" => std::process::Command::new("nc")
                    .args([
                        "-w", // timeout for connects and final net reads
                        "1",
                        TUN_IP_ADDR_STR,
                        SERVER_PORT.to_string().as_str(),
                    ])
                    .stdout(std::process::Stdio::piped())
                    .output(),
                "recvfrom" | "recvmsg" => std::process::Command::new("sh")
                    .args([
                        "-c",
                        &alloc::format!(
                            "echo -n '{buf}' | nc -w 1 {TUN_IP_ADDR_STR} {SERVER_PORT}",
                        ),
                    ])
                    .output(),
                _ => panic!("Unknown option"),
            }
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
        assert_eq!(remote_addr.ip().octets(), [10, 0, 0, 1]);
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
                    let mut events = [litebox_common_linux::EpollEvent::new(0, 0); 2];
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
                        let iovec = [litebox_common_linux::IoVec {
                            iov_base: UserPtrMut::from_usize(
                                recv_buf.as_mut_ptr().expose_provenance(),
                            ),
                            iov_len: recv_buf.len(),
                        }];
                        let mut msg_hdr = litebox_common_linux::UserMsgHdr::new_zeroed();
                        msg_hdr.msg_iov = UserPtr::from_usize(iovec.as_ptr() as usize);
                        msg_hdr.msg_iovlen = iovec.len();
                        let msg_ptr = UserPtrMut::from_usize(&raw mut msg_hdr as usize);
                        task.sys_recvmsg(i32::try_from(client_fd).unwrap(), msg_ptr, flags)
                            .expect("failed to recvmsg")
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

    fn test_tcp_socket_with_external_client(port: u16, is_nonblocking: bool, test_trunc: bool) {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        test_tcp_socket_as_server(
            &task,
            TUN_IP_ADDR,
            port,
            is_nonblocking,
            test_trunc,
            "recvfrom",
        );
        test_tcp_socket_as_server(
            &task,
            TUN_IP_ADDR,
            port,
            is_nonblocking,
            test_trunc,
            "recvmsg",
        );
    }

    fn test_tcp_socket_send(is_nonblocking: bool, test_trunc: bool) {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        test_tcp_socket_as_server(
            &task,
            TUN_IP_ADDR,
            SERVER_PORT,
            is_nonblocking,
            test_trunc,
            "sendto",
        );
        test_tcp_socket_as_server(
            &task,
            TUN_IP_ADDR,
            SERVER_PORT,
            is_nonblocking,
            test_trunc,
            "sendmsg",
        );
    }

    #[test]
    fn test_tun_blocking_send_tcp_socket() {
        test_tcp_socket_send(false, false);
    }

    #[test]
    fn test_tun_nonblocking_send_tcp_socket() {
        test_tcp_socket_send(true, false);
    }

    #[test]
    fn test_tun_blocking_recvfrom_tcp_socket() {
        test_tcp_socket_with_external_client(SERVER_PORT, false, false);
    }

    #[test]
    fn test_tun_nonblocking_recvfrom_tcp_socket() {
        test_tcp_socket_with_external_client(SERVER_PORT, true, false);
    }

    #[test]
    fn test_tun_blocking_recvfrom_tcp_socket_with_truncation() {
        test_tcp_socket_with_external_client(SERVER_PORT, false, true);
    }

    #[test]
    fn test_tun_tcp_connection_refused() {
        let task = init_platform(Some(TUN_DEVICE_NAME));
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
                    core::net::Ipv4Addr::from([10, 0, 0, 1]),
                    SERVER_PORT,
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
    fn test_tun_tcp_socket_as_client() {
        let task = init_platform(Some(TUN_DEVICE_NAME));

        let child_handle = std::thread::spawn(|| {
            std::process::Command::new("nc")
                .args([
                    "-w",
                    "1",
                    "-l",
                    "10.0.0.1",
                    SERVER_PORT.to_string().as_str(),
                ])
                .output()
        });
        std::thread::sleep(core::time::Duration::from_secs(1));

        // Client socket
        let client_fd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create client socket");

        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from([10, 0, 0, 1]),
            SERVER_PORT,
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

        let linger = litebox_common_linux::Linger {
            onoff: 1,   // enable linger
            linger: 60, // timeout in seconds
        };
        let optval = UserPtr::from_usize((&raw const linger).cast::<u8>() as usize);
        task.do_setsockopt(
            client_fd,
            SocketOptionName::Socket(SocketOption::LINGER),
            optval,
            core::mem::size_of::<litebox_common_linux::Linger>(),
        )
        .expect("Failed to set SO_LINGER");

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
            core::net::Ipv4Addr::from(TUN_IP_ADDR),
            SERVER_PORT,
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
                CLIENT_PORT.to_string().as_str(),
                TUN_IP_ADDR_STR,
                SERVER_PORT.to_string().as_str(),
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
            let mut events = [litebox_common_linux::EpollEvent::new(0, 0); 2];
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
        assert_eq!(sender_addr.port(), CLIENT_PORT);

        close_socket(task, server_fd);

        child.wait().expect("Failed to wait for client");
    }

    #[test]
    fn test_tun_blocking_udp_server_socket() {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        blocking_udp_server_socket(&task, false, false, false, "recvfrom");
        blocking_udp_server_socket(&task, false, false, false, "recvmsg");
    }

    #[test]
    fn test_tun_nonblocking_udp_server_socket() {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        blocking_udp_server_socket(&task, false, false, true, "recvfrom");
        blocking_udp_server_socket(&task, false, false, true, "recvmsg");
    }

    #[test]
    fn test_tun_blocking_udp_server_socket_with_truncation() {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        blocking_udp_server_socket(&task, true, true, false, "recvfrom");
        blocking_udp_server_socket(&task, true, true, false, "recvmsg");
        blocking_udp_server_socket(&task, true, false, false, "recvmsg");
    }

    #[test]
    fn test_tun_udp_client_socket_without_server() {
        // We do not support loopback yet, so this test only checks that
        // the client can send packets without a server.
        let task = init_platform(Some(TUN_DEVICE_NAME));

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
            SERVER_PORT,
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
    fn test_tun_tcp_sockopt() {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        let sockfd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create socket");

        let mut congestion_name = [0u8; 16];
        let optlen = task
            .do_getsockopt(
                sockfd,
                SocketOptionName::TCP(TcpOption::CONGESTION),
                UserPtrMut::from_usize(congestion_name.as_mut_ptr() as usize),
                congestion_name.len().trunc(),
            )
            .expect("Failed to get TCP_CONGESTION");
        assert_eq!(optlen, 4);
        assert_eq!(
            core::str::from_utf8(&congestion_name[..optlen]).unwrap(),
            "none"
        );

        task.do_setsockopt(
            sockfd,
            SocketOptionName::TCP(TcpOption::CONGESTION),
            UserPtr::from_usize(congestion_name.as_ptr() as usize),
            optlen,
        )
        .expect("Failed to set TCP_CONGESTION");

        let congestion_name = b"cubic\0";
        let err = task
            .do_setsockopt(
                sockfd,
                SocketOptionName::TCP(TcpOption::CONGESTION),
                UserPtr::from_usize(congestion_name.as_ptr() as usize),
                congestion_name.len(),
            )
            .unwrap_err();
        assert_eq!(err, Errno::EINVAL);

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
    }

    #[ignore = "timeout is 75s"]
    #[test]
    fn test_tun_tcp_so_error_network_unreachable() {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        let sockfd = task
            .do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0)
            .expect("failed to create socket");

        // Connect to an off-subnet IP (TEST-NET, 192.0.2.1).
        // smoltcp does not report errors when route table lookup fails. Instead, it just dicards the packets.
        // Our current implementation returns `ETIMEDOUT` instead of `ENETUNREACH`.
        let err = task
            .do_connect(
                sockfd,
                SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
                    core::net::Ipv4Addr::from([192, 0, 2, 1]),
                    SERVER_PORT,
                ))),
            )
            .unwrap_err();
        assert_eq!(err, Errno::ETIMEDOUT);

        let so_err = get_so_error(&task, sockfd);
        assert_eq!(so_err, i32::from(Errno::ETIMEDOUT).cast_unsigned());

        close_socket(&task, sockfd);
    }

    #[test]
    fn test_socket_dup_and_close() {
        let task = init_platform(None);
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

    #[test]
    fn test_setsockopt_broadcast_disable() {
        let task = init_platform(None);
        let sockfd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::empty(),
                0,
            )
            .expect("failed to create socket");

        let val: u32 = 1;
        let optval = UserPtr::from_usize((&raw const val).cast::<u8>() as usize);
        task.do_setsockopt(
            sockfd,
            SocketOptionName::Socket(SocketOption::BROADCAST),
            optval,
            core::mem::size_of::<u32>(),
        )
        .expect("failed to enable SO_BROADCAST");

        let val: u32 = 0;
        let optval = UserPtr::from_usize((&raw const val).cast::<u8>() as usize);
        task.do_setsockopt(
            sockfd,
            SocketOptionName::Socket(SocketOption::BROADCAST),
            optval,
            core::mem::size_of::<u32>(),
        )
        .expect("disabling SO_BROADCAST should succeed, not just enabling it");

        let mut result: u32 = 0xDEAD;
        let optval_out = UserPtrMut::from_usize((&raw mut result).cast::<u8>() as usize);
        let len = task
            .do_getsockopt(
                sockfd,
                SocketOptionName::Socket(SocketOption::BROADCAST),
                optval_out,
                core::mem::size_of::<u32>().trunc(),
            )
            .expect("failed to get SO_BROADCAST");
        assert_eq!(len, core::mem::size_of::<u32>());
        assert_eq!(result, 0, "SO_BROADCAST should reflect the disabled value");

        close_socket(&task, sockfd);
    }

    #[test]
    fn test_setsockopt_keepalive_udp_is_accepted_noop() {
        let task = init_platform(None);
        let sockfd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::empty(),
                0,
            )
            .expect("failed to create socket");

        let val: u32 = 1;
        let optval = UserPtr::from_usize((&raw const val).cast::<u8>() as usize);
        task.do_setsockopt(
            sockfd,
            SocketOptionName::Socket(SocketOption::KEEPALIVE),
            optval,
            core::mem::size_of::<u32>(),
        )
        .expect("SO_KEEPALIVE on a UDP socket should be accepted, like real Linux");

        let mut result: u32 = 0xDEAD;
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
        assert_eq!(result, 1, "the accepted value should still read back");

        close_socket(&task, sockfd);
    }

    #[test]
    fn test_write_sockaddr_to_user_ipv6() {
        let addr = core::net::SocketAddrV6::new(
            core::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            8080,
            0x1234_5678,
            7,
        );

        let mut buf = [0u8; 32];
        let mut addrlen: u32 = buf.len().trunc();
        write_sockaddr_to_user::<crate::syscalls::tests::TestPlatform>(
            SocketAddress::Inet(SocketAddr::V6(addr)),
            UserPtrMut::from_usize(buf.as_mut_ptr() as usize),
            UserPtrMut::from_usize((&raw mut addrlen) as usize),
        )
        .expect("write_sockaddr_to_user for IPv6 should succeed");

        assert_eq!(
            addrlen,
            u32::try_from(core::mem::size_of::<CSockInet6Addr>()).unwrap()
        );
        assert_eq!(
            u16::from_ne_bytes([buf[0], buf[1]]),
            AddressFamily::INET6 as u16
        );
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 8080);
        assert_eq!(
            u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            0x1234_5678
        );
        assert_eq!(&buf[8..24], &addr.ip().octets());
        assert_eq!(
            u32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]]),
            7,
            "scope_id is a local interface index, not swapped to network byte order"
        );

        // A too-small buffer still succeeds, copies only what fits, and reports the
        // true (untruncated) size back through addrlen -- mirroring the pre-existing
        // IPv4 truncation behavior in this same function.
        let mut small_buf = [0xAAu8; 10];
        let mut small_addrlen: u32 = small_buf.len().trunc();
        write_sockaddr_to_user::<crate::syscalls::tests::TestPlatform>(
            SocketAddress::Inet(SocketAddr::V6(addr)),
            UserPtrMut::from_usize(small_buf.as_mut_ptr() as usize),
            UserPtrMut::from_usize((&raw mut small_addrlen) as usize),
        )
        .expect("truncated write_sockaddr_to_user for IPv6 should still succeed");
        assert_eq!(
            small_addrlen,
            u32::try_from(core::mem::size_of::<CSockInet6Addr>()).unwrap()
        );
        assert_eq!(&small_buf[..], &buf[..10]);
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
        AddressFamily, AtFlags, FileDescriptorFlags, ReceiveFlags, SendFlags, SockFlags, SockType,
        SocketOption, SocketOptionLevel, SocketOptionName, TimeParam, errno::Errno,
    };
    use zerocopy::FromZeros as _;

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

    #[test]
    fn unknown_getsockopt_returns_enoprotoopt() {
        const SO_PEERPIDFD: u32 = 77;

        let task = init_platform(None);
        let socket = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let mut value = 0u32;
        let mut len = u32::try_from(core::mem::size_of_val(&value)).unwrap();

        let error = task
            .sys_getsockopt(
                socket.try_into().unwrap(),
                SocketOptionLevel::SOCKET as u32,
                SO_PEERPIDFD,
                UserPtrMut::from_usize((&raw mut value).cast::<u8>() as usize),
                UserPtrMut::from_usize(&raw mut len as usize),
            )
            .unwrap_err();

        assert_eq!(error, Errno::ENOPROTOOPT);
        close_socket(&task, socket);
    }

    #[test]
    fn unix_stream_peercred_uses_credentials_at_listen() {
        let task = init_platform(None);
        let name = b"unix_peercred_listen_time".to_vec();
        let server = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        task.do_bind(
            server,
            SocketAddress::Unix(UnixSocketAddr::Abstract(name.clone())),
        )
        .expect("bind server socket");

        task.sys_setuid(1000)
            .expect("change credentials before listen");
        task.do_listen(server, 1).expect("listen on server socket");

        let client = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        task.do_connect(client, SocketAddress::Unix(UnixSocketAddr::Abstract(name)))
            .expect("connect client socket");
        let accepted = task
            .do_accept(server, None, SockFlags::empty())
            .expect("accept client socket");

        let peer_cred = |fd| {
            let mut value = litebox_common_linux::Ucred {
                pid: u32::MAX,
                uid: u32::MAX,
                gid: u32::MAX,
            };
            let len = task
                .do_getsockopt(
                    fd,
                    SocketOptionName::Socket(SocketOption::PEERCRED),
                    UserPtrMut::from_usize((&raw mut value).cast::<u8>() as usize),
                    u32::try_from(core::mem::size_of_val(&value)).unwrap(),
                )
                .expect("getsockopt SO_PEERCRED");
            assert_eq!(len, core::mem::size_of_val(&value));
            value
        };
        let server_cred = peer_cred(client);
        let client_cred = peer_cred(accepted);
        let expected_pid = u32::try_from(task.pid).unwrap();
        assert_eq!((server_cred.pid, server_cred.uid), (expected_pid, 1000));
        assert_eq!((client_cred.pid, client_cred.uid), (expected_pid, 1000));

        close_socket(&task, accepted);
        close_socket(&task, client);
        close_socket(&task, server);
    }

    #[test]
    fn scm_rights_transfers_open_description_and_receive_cloexec() {
        const SOL_SOCKET: u32 = 1;
        const SCM_RIGHTS: u32 = 1;
        const CMSG_HEADER_LEN: usize =
            core::mem::size_of::<usize>() + 2 * core::mem::size_of::<u32>();
        const CMSG_LEN_ONE_FD: usize = CMSG_HEADER_LEN + core::mem::size_of::<i32>();
        const CMSG_SPACE_ONE_FD: usize = (CMSG_LEN_ONE_FD + core::mem::size_of::<usize>() - 1)
            & !(core::mem::size_of::<usize>() - 1);

        for receive_cloexec in [false, true] {
            let task = init_platform(None);
            let (bus_sender, bus_receiver) = task
                .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0)
                .expect("transport socketpair failed");
            let (payload_sender, payload_peer) = task
                .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::CLOEXEC, 0)
                .expect("payload socketpair failed");

            let data = *b"F";
            let send_iov = [litebox_common_linux::IoVec {
                iov_base: UserPtrMut::from_usize(data.as_ptr() as usize),
                iov_len: data.len(),
            }];
            let mut send_control = [0u8; CMSG_SPACE_ONE_FD];
            send_control[..core::mem::size_of::<usize>()]
                .copy_from_slice(&CMSG_LEN_ONE_FD.to_ne_bytes());
            let level_offset = core::mem::size_of::<usize>();
            let type_offset = level_offset + core::mem::size_of::<u32>();
            send_control[level_offset..type_offset].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
            send_control[type_offset..CMSG_HEADER_LEN].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
            send_control[CMSG_HEADER_LEN..CMSG_LEN_ONE_FD]
                .copy_from_slice(&i32::try_from(payload_sender).unwrap().to_ne_bytes());
            let mut send_header = litebox_common_linux::UserMsgHdr::new_zeroed();
            send_header.msg_iov = UserPtr::from_usize(send_iov.as_ptr() as usize);
            send_header.msg_iovlen = send_iov.len();
            send_header.msg_control = UserPtr::from_usize(send_control.as_ptr() as usize);
            send_header.msg_controllen = send_control.len();

            task.sys_sendmsg(
                i32::try_from(bus_sender).unwrap(),
                UserPtr::from_usize(&raw const send_header as usize),
                SendFlags::NOSIGNAL,
            )
            .expect("SCM_RIGHTS sendmsg failed");
            close_socket(&task, payload_sender);

            let mut received_data = [0u8; 1];
            let recv_iov = [litebox_common_linux::IoVec {
                iov_base: UserPtrMut::from_usize(received_data.as_mut_ptr() as usize),
                iov_len: received_data.len(),
            }];
            let mut recv_control = [0u8; CMSG_SPACE_ONE_FD];
            let mut recv_header = litebox_common_linux::UserMsgHdr::new_zeroed();
            recv_header.msg_iov = UserPtr::from_usize(recv_iov.as_ptr() as usize);
            recv_header.msg_iovlen = recv_iov.len();
            recv_header.msg_control = UserPtr::from_usize(recv_control.as_mut_ptr() as usize);
            recv_header.msg_controllen = recv_control.len();
            let recv_flags = if receive_cloexec {
                ReceiveFlags::CMSG_CLOEXEC
            } else {
                ReceiveFlags::empty()
            };

            let received = task
                .sys_recvmsg(
                    i32::try_from(bus_receiver).unwrap(),
                    UserPtrMut::from_usize(&raw mut recv_header as usize),
                    recv_flags,
                )
                .expect("SCM_RIGHTS recvmsg failed");
            assert_eq!(received, 1);
            assert_eq!(received_data, data);
            let returned_controllen = recv_header.msg_controllen;
            let returned_flags = recv_header.msg_flags;
            assert_eq!(returned_controllen, CMSG_SPACE_ONE_FD);
            assert!(!returned_flags.contains(ReceiveFlags::CTRUNC));
            assert_eq!(
                usize::from_ne_bytes(
                    recv_control[..core::mem::size_of::<usize>()]
                        .try_into()
                        .unwrap()
                ),
                CMSG_LEN_ONE_FD
            );
            assert_eq!(
                u32::from_ne_bytes(recv_control[level_offset..type_offset].try_into().unwrap()),
                SOL_SOCKET
            );
            assert_eq!(
                u32::from_ne_bytes(
                    recv_control[type_offset..CMSG_HEADER_LEN]
                        .try_into()
                        .unwrap()
                ),
                SCM_RIGHTS
            );
            let received_fd = i32::from_ne_bytes(
                recv_control[CMSG_HEADER_LEN..CMSG_LEN_ONE_FD]
                    .try_into()
                    .unwrap(),
            );
            let descriptor_flags = {
                let files = task.files.borrow();
                crate::syscalls::file::get_file_descriptor_flags(
                    usize::try_from(received_fd).unwrap(),
                    &task.global,
                    &files,
                )
                .expect("F_GETFD failed")
            };
            assert_eq!(
                descriptor_flags.contains(FileDescriptorFlags::FD_CLOEXEC),
                receive_cloexec
            );

            task.do_sendto(payload_peer, b"alive", SendFlags::empty(), None)
                .expect("send through payload peer failed");
            let mut payload = [0u8; 5];
            let payload_len = task
                .do_recvfrom(
                    u32::try_from(received_fd).unwrap(),
                    &mut payload,
                    ReceiveFlags::empty(),
                    None,
                )
                .expect("received descriptor is unusable");
            assert_eq!(&payload[..payload_len], b"alive");

            close_socket(&task, u32::try_from(received_fd).unwrap());
            close_socket(&task, payload_peer);
            close_socket(&task, bus_sender);
            close_socket(&task, bus_receiver);
        }
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
        let task = init_platform(None);

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
        let task = init_platform(None);

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
        let task = init_platform(None);
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
        let task = init_platform(None);
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
        let task = init_platform(None);
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
        let task = init_platform(None);
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

    // -- Regression coverage for the previously-missed unix-addr-table gap --
    //
    // Before this fix, `task.global.unix_addr_table` was only ever populated
    // by `listen()` (stream sockets) and `UnixDatagramInner::bind()`
    // (datagram sockets). A plain stream socket that called `bind()` but had
    // not (yet) called `listen()` -- the ordinary client-role
    // autobind-then-connect pattern -- was never inserted into the table at
    // all, so a second, colliding bind was invisible to collision detection
    // and could succeed anyway. Separately, `UnixSocketAddr::Abstract`'s
    // explicit-bind arm had *zero* collision detection (a bare `TODO`), and
    // the read-then-separate-write table access elsewhere was a
    // check-then-act race. The tests below exercise exactly those three
    // gaps against the real syscall surface (`do_bind`/`do_connect`), not
    // against any internal helper.

    #[test]
    fn test_unix_stream_abstract_bind_without_listen_blocks_collision() {
        let task = init_platform(None);
        let name = b"gm_third_attempt_abstract_addr".to_vec();

        // Socket A explicitly binds an abstract address but never calls
        // listen(). This is exactly the gap the prior attempt's own fix
        // missed: only listen()/datagram-bind() ever touched the shared
        // address table, so a bound-but-not-listening socket was invisible
        // to collision detection.
        let a_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        task.do_bind(
            a_fd,
            SocketAddress::Unix(UnixSocketAddr::Abstract(name.clone())),
        )
        .expect("first abstract bind should succeed");

        // A second socket colliding on the same abstract address must be
        // rejected while A is alive, even though A never listened. The
        // pre-existing `Abstract` bind arm had zero collision detection at
        // all (a bare `TODO`), so this is also the abstract-collision case.
        let b_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let err = task
            .do_bind(
                b_fd,
                SocketAddress::Unix(UnixSocketAddr::Abstract(name.clone())),
            )
            .unwrap_err();
        assert_eq!(err, Errno::EADDRINUSE);

        // Once A closes (still never having listened), the address must
        // become free again for a fresh bind.
        close_socket(&task, a_fd);
        task.do_bind(b_fd, SocketAddress::Unix(UnixSocketAddr::Abstract(name)))
            .expect("bind should succeed once A releases the address");

        close_socket(&task, b_fd);
    }

    #[test]
    fn test_unix_stream_path_bind_without_listen_blocks_collision() {
        let task = init_platform(None);
        let addr = "/unix_bind_no_listen_path.sock";

        let a_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        task.do_bind(
            a_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        )
        .expect("first bind should succeed");

        let b_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let err = task
            .do_bind(
                b_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap_err();
        assert_eq!(err, Errno::EADDRINUSE);

        close_socket(&task, a_fd);
        task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
        task.do_bind(
            b_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        )
        .expect("bind should succeed once A is gone and the path is unlinked");

        close_socket(&task, b_fd);
        task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
    }

    #[test]
    fn test_unix_bound_client_reservation_survives_into_connected_state() {
        let task = init_platform(None);
        let server_path = "/unix_client_reservation_server.sock";
        let server_fd = create_unix_server_socket(&task, server_path, SockFlags::empty()).unwrap();

        let client_name = b"gm_third_attempt_client_addr".to_vec();
        let client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        task.do_bind(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Abstract(client_name.clone())),
        )
        .expect("client bind should succeed");

        // Client connects without ever calling listen() -- the "ordinary
        // client-role autobind-then-connect pattern" the bug report names
        // directly.
        task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .unwrap();

        // The client's own bound address must still be reserved while the
        // connection is alive -- a second socket must not be able to steal
        // it just because the client stopped being in "Init" state.
        let other_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let err = task
            .do_bind(
                other_fd,
                SocketAddress::Unix(UnixSocketAddr::Abstract(client_name.clone())),
            )
            .unwrap_err();
        assert_eq!(err, Errno::EADDRINUSE);

        // Closing the connected client releases its reservation.
        close_socket(&task, client_fd);
        task.do_bind(
            other_fd,
            SocketAddress::Unix(UnixSocketAddr::Abstract(client_name)),
        )
        .expect("bind should succeed once the connected client closes");

        close_socket(&task, other_fd);
        let server_conn = task.do_accept(server_fd, None, SockFlags::empty()).unwrap();
        close_socket(&task, server_conn);
        close_socket(&task, server_fd);
        task.sys_unlinkat(-1, server_path, AtFlags::empty())
            .unwrap();
    }

    #[test]
    fn test_unix_concurrent_bind_same_abstract_address_exactly_one_wins() {
        let task = init_platform(None);

        for i in 0..20 {
            let name = alloc::format!("gm_race_addr_{i}").into_bytes();
            let a_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            let b_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let barrier_a = barrier.clone();
            let name_a = name.clone();

            // Both threads race to bind the *same* address, synchronized to
            // maximize the chance of hitting the window a check-then-act
            // race (read the table, then write, as two separate critical
            // sections) would allow -- both observing the address as free
            // and both succeeding.
            let handle = task.spawn_clone_for_test(move |task| {
                barrier_a.wait();
                task.do_bind(a_fd, SocketAddress::Unix(UnixSocketAddr::Abstract(name_a)))
            });

            barrier.wait();
            let result_b = task.do_bind(b_fd, SocketAddress::Unix(UnixSocketAddr::Abstract(name)));
            let result_a = handle.join().expect("thread A panicked");

            let wins = usize::from(result_a.is_ok()) + usize::from(result_b.is_ok());
            assert_eq!(
                wins, 1,
                "exactly one concurrent bind to the same address must succeed, got a={result_a:?} b={result_b:?}"
            );

            close_socket(&task, a_fd);
            close_socket(&task, b_fd);
        }
    }

    #[test]
    fn test_unix_concurrent_bind_different_addresses_both_succeed() {
        let task = init_platform(None);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let barrier_a = barrier.clone();

        let a_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let b_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let name_a = b"gm_concurrent_addr_a".to_vec();
        let name_b = b"gm_concurrent_addr_b".to_vec();
        let name_a2 = name_a.clone();

        // Two unrelated binds proceeding concurrently must not spuriously
        // collide with each other -- the shared table's write-lock critical
        // sections are per-attempt and brief (see `reserve_unix_addr`), not
        // one coarse lock serializing every bind against every other.
        let handle = task.spawn_clone_for_test(move |task| {
            barrier_a.wait();
            task.do_bind(a_fd, SocketAddress::Unix(UnixSocketAddr::Abstract(name_a2)))
        });

        barrier.wait();
        let result_b = task.do_bind(b_fd, SocketAddress::Unix(UnixSocketAddr::Abstract(name_b)));
        let result_a = handle.join().expect("thread A panicked");

        assert!(
            result_a.is_ok(),
            "bind to address A should succeed: {result_a:?}"
        );
        assert!(
            result_b.is_ok(),
            "bind to address B should succeed: {result_b:?}"
        );

        close_socket(&task, a_fd);
        close_socket(&task, b_fd);
    }

    #[test]
    fn test_unix_stream_autobind_assigns_unique_addresses() {
        let task = init_platform(None);
        let mut seen = Vec::new();
        for _ in 0..64 {
            let fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            task.do_bind(fd, SocketAddress::Unix(UnixSocketAddr::Unnamed))
                .expect("autobind should succeed");
            let addr = task.do_getsockname(fd).unwrap();
            let SocketAddress::Unix(UnixSocketAddr::Abstract(name)) = addr else {
                panic!("autobind should assign an abstract address, got {addr:?}");
            };
            assert!(
                !seen.contains(&name),
                "two autobinds must not collide on the same abstract address"
            );
            seen.push(name);
            close_socket(&task, fd);
        }
    }

    fn unix_socketpair_bidirectional(ty: SockType, is_nonblocking: bool) {
        let task = init_platform(None);
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
        unix_socketpair_bidirectional(SockType::SeqPacket, false);

        unix_socketpair_bidirectional(SockType::Stream, true);
        unix_socketpair_bidirectional(SockType::Datagram, true);
        unix_socketpair_bidirectional(SockType::SeqPacket, true);
    }

    #[test]
    fn test_unix_seqpacket_socketpair_preserves_records_and_reports_type() {
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(
                AddressFamily::UNIX,
                SockType::SeqPacket,
                SockFlags::CLOEXEC,
                0,
            )
            .expect("SOCK_SEQPACKET socketpair failed");

        for fd in [sock1, sock2] {
            let mut socket_type = 0u32;
            let len = task
                .do_getsockopt(
                    fd,
                    SocketOptionName::Socket(SocketOption::TYPE),
                    UserPtrMut::from_usize((&raw mut socket_type).cast::<u8>() as usize),
                    u32::try_from(core::mem::size_of::<u32>()).unwrap(),
                )
                .expect("SO_TYPE failed");
            assert_eq!(len, core::mem::size_of::<u32>());
            assert_eq!(socket_type, SockType::SeqPacket as u32);
        }

        let first = b"first record";
        let second = b"second record";
        task.do_sendto(sock1, first, SendFlags::empty(), None)
            .expect("first send failed");
        task.do_sendto(sock1, second, SendFlags::empty(), None)
            .expect("second send failed");

        let mut buf = [0u8; 64];
        let n = task
            .do_recvfrom(sock2, &mut buf, ReceiveFlags::empty(), None)
            .expect("first receive failed");
        assert_eq!(n, first.len());
        assert_eq!(&buf[..n], first);

        let n = task
            .do_recvfrom(sock2, &mut buf, ReceiveFlags::empty(), None)
            .expect("second receive failed");
        assert_eq!(n, second.len());
        assert_eq!(&buf[..n], second);

        let oversized = b"truncate this record";
        task.do_sendto(sock1, oversized, SendFlags::empty(), None)
            .expect("oversized send failed");
        let mut short = [0u8; 5];
        let n = task
            .do_recvfrom(sock2, &mut short, ReceiveFlags::empty(), None)
            .expect("truncated receive failed");
        assert_eq!(n, oversized.len());
        assert_eq!(&short, &oversized[..short.len()]);

        close_socket(&task, sock1);
        let n = task
            .do_recvfrom(sock2, &mut buf, ReceiveFlags::empty(), None)
            .expect("peer close must become EOF");
        assert_eq!(n, 0);
        close_socket(&task, sock2);
    }

    fn unix_socket_recv_timeout(ty: SockType) {
        let task = init_platform(None);
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
        unix_socket_recv_timeout(SockType::SeqPacket);
    }

    #[test]
    fn test_unix_stream_addr() {
        let task = init_platform(None);
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
        let task = init_platform(None);
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
