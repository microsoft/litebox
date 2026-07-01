// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg_attr(
    not(feature = "worker_local_inet"),
    allow(dead_code, unused_imports, unused_macros)
)]
//! Socket-related syscalls, e.g., socket, bind, listen, etc.

use core::{
    ffi::CStr,
    mem::offset_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use alloc::sync::Arc;
use alloc::{string::String, string::ToString, vec::Vec};
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
        socket_channel::{NetworkProxy, SocketState},
    },
    platform::IPInterfaceProvider as _,
    platform::{RawConstPointer as _, RawMutPointer as _},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    AddressFamily, FileDescriptorFlags, IPProtocol, ReceiveFlags, SendFlags, SockFlags, SockType,
    SocketOption, SocketOptionName, TcpOption, UnixProtocol, errno::Errno,
    fd_transfer_frame::FdTransferFrame,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::{ConstPtr, MutPtr};
use crate::{GlobalState, ShimFS, Task};
use crate::{
    Platform,
    syscalls::unix::{CSockUnixAddr, UnixSocket, UnixSocketAddr},
};

/// Linux default for `TCP_KEEPIDLE` (seconds before first keep-alive probe).
const DEFAULT_TCP_KEEPIDLE_SECS: u32 = 7200;
/// Linux default for `TCP_KEEPCNT` (number of unacknowledged probes before drop).
const DEFAULT_TCP_KEEPCNT: u32 = 9;

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

pub(crate) type SocketFd = litebox::net::SocketFd<Platform>;
type BrokerSocketPairTypedFd =
    litebox::fd::TypedFd<crate::syscalls::broker_socketpair::BrokerSocketPairSubsystem>;
type BrokerSocketPairHandle = litebox::fd::EntryHandle<
    Platform,
    crate::syscalls::broker_socketpair::BrokerSocketPairSubsystem,
>;
type BrokerSocketDgramTypedFd =
    litebox::fd::TypedFd<crate::syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem>;
type BrokerSocketDgramHandle = litebox::fd::EntryHandle<
    Platform,
    crate::syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem,
>;
type BrokerSocketSeqPacketTypedFd =
    litebox::fd::TypedFd<crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>;
type BrokerSocketSeqPacketHandle = litebox::fd::EntryHandle<
    Platform,
    crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem,
>;
type BrokerUnixStreamTypedFd =
    litebox::fd::TypedFd<crate::syscalls::broker_unix_stream::BrokerUnixStreamSubsystem>;
type BrokerUnixStreamHandle = litebox::fd::EntryHandle<
    Platform,
    crate::syscalls::broker_unix_stream::BrokerUnixStreamSubsystem,
>;
type BrokerTcpConnTypedFd =
    litebox::fd::TypedFd<crate::syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>;
type BrokerTcpConnHandle =
    litebox::fd::EntryHandle<Platform, crate::syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>;
type BrokerInetListenerTypedFd =
    litebox::fd::TypedFd<crate::syscalls::broker_inet_listener::BrokerInetListenerSubsystem>;
type BrokerInetListenerHandle = litebox::fd::EntryHandle<
    Platform,
    crate::syscalls::broker_inet_listener::BrokerInetListenerSubsystem,
>;
type BrokerInetDgramTypedFd =
    litebox::fd::TypedFd<crate::syscalls::broker_inet_dgram::BrokerInetDgramSubsystem>;
type BrokerInetDgramHandle = litebox::fd::EntryHandle<
    Platform,
    crate::syscalls::broker_inet_dgram::BrokerInetDgramSubsystem,
>;

impl<FS: ShimFS> super::file::FilesState<FS> {
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
    pub(super) fn with_socket<R>(
        &self,
        global: &GlobalState<FS>,
        sockfd: u32,
        inet_op: impl FnOnce(&SocketFd) -> Result<R, Errno>,
        unix_op: impl FnOnce(&UnixSocket<FS>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let raw_fd = sockfd as usize;
        let inet_fd = {
            let rds = self.raw_descriptor_store.read();
            rds.fd_from_raw_integer(raw_fd).ok()
        };
        if let Some(fd) = inet_fd {
            return inet_op(&fd);
        }
        // Resolve the fd in an inner scope so the `raw_descriptor_store`
        // read guard is released BEFORE the `map_err` error path runs.
        // `assert_no_unhandled_socket_subsystem` (in the `InvalidSubsystem`
        // arm) re-reads `raw_descriptor_store`; holding the guard across it
        // is a re-entrant read on the writer-preferring RwLock that
        // self-deadlocks if a writer queues between (same class as
        // `a863a31f`). `fd_from_raw_integer` returns an owned handle, so it
        // safely outlives the guard.
        let unix = {
            let rds = self.raw_descriptor_store.read();
            rds.fd_from_raw_integer::<crate::syscalls::unix::UnixSocketSubsystem<FS>>(raw_fd)
        }
        .map_err(|err| match err {
            litebox::fd::ErrRawIntFd::NotFound => Errno::EBADF,
            litebox::fd::ErrRawIntFd::InvalidSubsystem => {
                // PE.11 invariant: if we reach this branch, the fd
                // exists in the descriptor table as SOME subsystem
                // that's neither INET nor shim-Unix. For
                // socket-like subsystems (BrokerSocketPair today,
                // future broker-backed Unix variants), returning
                // ENOTSOCK silently is the same class of bug that
                // caused tokio's "Bad read on self-pipe: ENOTSOCK"
                // panic under eager-broker-socketpair (PE.10).
                // The caller of with_socket should have dispatched
                // them BEFORE entering with_socket.
                //
                // For genuinely-not-a-socket subsystems (regular
                // file, pipe, eventfd, signalfd, epoll, host-passthrough-fd),
                // ENOTSOCK is the correct errno per POSIX.
                //
                // assert_socket_like_handled() panics if the fd's
                // subsystem is one we've classified as socket-like
                // and forgot to dispatch — converting a silent
                // mis-routing into a loud bug. Always-on (release-
                // build too).
                assert_no_unhandled_socket_subsystem::<FS>(&self.raw_descriptor_store, raw_fd);
                Errno::ENOTSOCK
            }
        })?;
        let handle = global
            .litebox
            .descriptor_table()
            .entry_handle(&unix)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(|entry| unix_op(entry))
    }
}

/// PE.11 invariant helper: panics if `raw_fd` resolves to a
/// subsystem that's been classified as "socket-like" but wasn't
/// dispatched by [`FilesState::with_socket`]. The canonical
/// failure caught is `BrokerSocketPairSubsystem` (Phase F broker-
/// backed AF_UNIX socketpair) being routed through with_socket
/// without an explicit fast path — which is exactly how tokio's
/// "Bad read on self-pipe: ENOTSOCK" panic surfaced under eager-
/// broker-socketpair.
///
/// When future broker-backed socket-like subsystems (e.g. broker-
/// backed inet, broker-backed seqpacket) are added, append them
/// to the match. The compiler doesn't enforce exhaustiveness over
/// "subsystems with the socket-like property" (no central enum
/// classifies them), so we list explicitly and rely on this
/// assertion + the PE.5 / PE.10 / PE.11 commit comments to keep
/// the list aware.
fn assert_no_unhandled_socket_subsystem<FS: ShimFS>(
    raw_descriptor_store: &litebox::sync::RwLock<
        litebox_platform_multiplex::Platform,
        litebox::fd::RawDescriptorStorage,
    >,
    raw_fd: usize,
) {
    let rds = raw_descriptor_store.read();
    if rds
        .fd_from_raw_integer::<crate::syscalls::broker_socketpair::BrokerSocketPairSubsystem>(
            raw_fd,
        )
        .is_ok()
    {
        panic!(
            "with_socket: fd={raw_fd} is a BrokerSocketPairSubsystem entry — \
             the caller must dispatch broker-backed socketpair fds BEFORE \
             calling with_socket (see PE.10 recv() fast path in do_recvfrom_with_fds)"
        );
    }
    if rds
        .fd_from_raw_integer::<crate::syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem>(
            raw_fd,
        )
        .is_ok()
    {
        panic!(
            "with_socket: fd={raw_fd} is a BrokerSocketDgramSubsystem entry — \
             the caller must dispatch broker-backed unix dgram fds BEFORE calling with_socket"
        );
    }
    if rds
        .fd_from_raw_integer::<crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(
            raw_fd,
        )
        .is_ok()
    {
        panic!(
            "with_socket: fd={raw_fd} is a BrokerSocketSeqPacketSubsystem entry — \
             the caller must dispatch broker-backed unix seqpacket fds BEFORE calling with_socket"
        );
    }
    if rds
        .fd_from_raw_integer::<crate::syscalls::broker_inet_listener::BrokerInetListenerSubsystem>(
            raw_fd,
        )
        .is_ok()
    {
        panic!(
            "with_socket: fd={raw_fd} is a BrokerInetListenerSubsystem entry — \
             the caller must dispatch broker-backed inet listener fds BEFORE calling with_socket"
        );
    }
    if rds
        .fd_from_raw_integer::<crate::syscalls::broker_inet_raw::BrokerInetRawSubsystem>(raw_fd)
        .is_ok()
    {
        panic!(
            "with_socket: fd={raw_fd} is a BrokerInetRawSubsystem entry — \
             the caller must dispatch broker-backed inet raw fds BEFORE calling with_socket"
        );
    }
    // No socket-like subsystem matched → genuine ENOTSOCK.
}

#[derive(Clone, Copy, FromBytes, IntoBytes)]
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

fn socket_option_raw(optname: SocketOptionName) -> (u32, u32) {
    match optname {
        SocketOptionName::IP(ip) => (0, ip as u32),
        SocketOptionName::IPv6(ipv6) => (41, ipv6 as u32),
        SocketOptionName::Socket(socket) => (1, socket as u32),
        SocketOptionName::TCP(tcp) => (IPProtocol::TCP as u32, tcp as u32),
    }
}

fn passthrough_sockopt_value(level: u32, optname: u32) -> Option<u32> {
    match SocketOptionName::try_from(level, optname)? {
        SocketOptionName::Socket(SocketOption::SNDBUF | SocketOption::RCVBUF) => Some(64u32 * 1024),
        SocketOptionName::TCP(TcpOption::NODELAY) => Some(1),
        SocketOptionName::IP(_)
        | SocketOptionName::IPv6(_)
        | SocketOptionName::Socket(_)
        | SocketOptionName::TCP(_) => None,
    }
}

fn linux_set_to_reported_socket_buffer_value(value: u32) -> u32 {
    value.saturating_mul(2)
}

impl SocketAddress {
    pub(crate) fn inet(self) -> Option<SocketAddr> {
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match self {
            SocketAddress::Inet(addr) => Some(addr),
            _ => None,
        }
    }

    pub(crate) fn unix(self) -> Option<UnixSocketAddr> {
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match self {
            SocketAddress::Unix(addr) => Some(addr),
            _ => None,
        }
    }
}

#[derive(Default, Clone)]
pub(super) struct SocketOptions {
    pub(super) reuse_address: bool,
    pub(super) reuse_port: bool,
    pub(super) keep_alive: bool,
    pub(super) broadcast: bool,
    pub(super) send_buffer_size: Option<u32>,
    pub(super) recv_buffer_size: Option<u32>,
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

#[derive(Clone, Copy)]
pub(crate) struct SocketOFlags(pub OFlags);
#[derive(Clone)]
pub(crate) struct SocketProxy(pub Arc<NetworkProxy<Platform>>);

pub(super) enum SocketOptionValue {
    Timeout(Option<core::time::Duration>),
    U32(u32),
}

/// Socket-related implementation. Currently these methods are on `GlobalState`
/// so that they can access `net` and the litebox descriptor table. This might
/// change if the nature of the litebox descriptor table changes, or if network
/// namespaces are implemented.
impl<FS: ShimFS> GlobalState<FS> {
    #[cfg(feature = "worker_local_inet")]
    pub(crate) fn initialize_socket(
        &self,
        fd: &SocketFd,
        sock_type: SockType,
        flags: SockFlags,
    ) -> Arc<NetworkProxy<litebox_platform_multiplex::Platform>> {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));

        let mut dt = self.litebox.descriptor_table_mut();
        let old = dt.set_entry_metadata(fd, SocketOptions::default());
        assert!(old.is_none());
        if flags.contains(SockFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(fd, litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        let old = dt.set_fd_metadata(fd, sock_type);
        assert!(old.is_none());
        let old = dt.set_entry_metadata(fd, SocketOFlags(status));
        assert!(old.is_none());

        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
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
            _ => unimplemented!(),
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

    #[cfg(feature = "worker_local_inet")]
    fn with_socket_options<R>(&self, fd: &SocketFd, f: impl FnOnce(&SocketOptions) -> R) -> R {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |opt| f(opt))
            .unwrap()
    }
    #[cfg(feature = "worker_local_inet")]
    fn with_socket_options_mut<R>(
        &self,
        fd: &SocketFd,
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
        optval: ConstPtr<u8>,
        optlen: usize,
        set_option: F,
    ) -> Result<(), Errno>
    where
        F: FnOnce(SocketOption, SocketOptionValue) -> Result<(), Errno>,
    {
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        match optname {
            SocketOptionName::Socket(sopt) => match sopt {
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO => {
                    let timeval =
                        super::read_from_user::<litebox_common_linux::TimeVal>(optval, optlen)?;
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
                        super::read_from_user(optval, optlen)?;
                    let timeout = if linger.onoff != 0 {
                        Some(core::time::Duration::from_secs(u64::from(linger.linger)))
                    } else {
                        None
                    };
                    set_option(sopt, SocketOptionValue::Timeout(timeout))
                }
                SocketOption::REUSEADDR
                | SocketOption::REUSEPORT
                | SocketOption::BROADCAST
                | SocketOption::KEEPALIVE
                | SocketOption::SNDBUF
                | SocketOption::RCVBUF => {
                    let val: u32 = super::read_from_user(optval, optlen)?;
                    set_option(sopt, SocketOptionValue::U32(val))
                }
                _ => Err(Errno::ENOPROTOOPT),
            },
            _ => Err(Errno::ENOPROTOOPT),
        }
    }
    #[cfg(feature = "worker_local_inet")]
    fn setsockopt(
        &self,
        fd: &SocketFd,
        optname: SocketOptionName,
        optval: ConstPtr<u8>,
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
                    (SocketOption::REUSEPORT, SocketOptionValue::U32(val)) => {
                        opt.reuse_port = val != 0;
                    }
                    (SocketOption::BROADCAST, SocketOptionValue::U32(val)) => {
                        opt.broadcast = val != 0;
                        if val == 0 {
                            todo!("disable SO_BROADCAST");
                        }
                    }
                    (SocketOption::SNDBUF, SocketOptionValue::U32(val)) => {
                        opt.send_buffer_size = Some(linux_set_to_reported_socket_buffer_value(val));
                    }
                    (SocketOption::RCVBUF, SocketOptionValue::U32(val)) => {
                        opt.recv_buffer_size = Some(linux_set_to_reported_socket_buffer_value(val));
                    }
                    (SocketOption::KEEPALIVE, SocketOptionValue::U32(val)) => {
                        let keep_alive = val != 0;
                        deferred_tcp_option = Some(if keep_alive {
                            // default time interval is 2 hours
                            litebox::net::TcpOptionData::KEEPALIVE(Some(
                                core::time::Duration::from_secs(2 * 60 * 60),
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
                    litebox::net::errors::SetTcpOptionError::NotTcpSocket => {
                        unimplemented!("SO_KEEPALIVE is not supported for non-TCP sockets")
                    }
                    _ => unimplemented!(),
                }
            }
            Ok(())
        }) {
            Err(Errno::ENOPROTOOPT) => {} // fallthrough to handle other options
            other => {
                return other;
            }
        }

        match optname {
            SocketOptionName::IP(ip) => match ip {
                // Silently accept IP_TOS (traffic class hint). Node's
                // Socket.setTypeOfService treats ENOTSUP as an uncaught
                // exception and tears down the connection. We don't
                // propagate the TOS bit anywhere, but accepting the
                // setsockopt is harmless and matches what most Linux
                // configurations do for unprivileged sockets.
                litebox_common_linux::IpOption::TOS => return Ok(()),
                // Silently accept IP_RECVERR, IP_MTU_DISCOVER, IP_PKTINFO
                // (used by glibc's DNS resolver; not yet tracked).
                litebox_common_linux::IpOption::RECVERR
                | litebox_common_linux::IpOption::MTU_DISCOVER
                | litebox_common_linux::IpOption::PKTINFO => return Ok(()),
            },
            SocketOptionName::Socket(so) => match so {
                // handled by `setsockopt_common`
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::REUSEPORT
                | SocketOption::BROADCAST
                | SocketOption::KEEPALIVE
                | SocketOption::RCVBUF
                | SocketOption::SNDBUF => unreachable!(),
                // Socket does not support these options
                SocketOption::TYPE | SocketOption::PEERCRED | SocketOption::ERROR => {
                    return Err(Errno::ENOPROTOOPT);
                }
            },
            SocketOptionName::IPv6(litebox_common_linux::Ipv6Option::V6ONLY) => {
                let _val: u32 = super::read_from_user(optval, optlen)?;
                return Ok(());
            }
            SocketOptionName::TCP(to) => match to {
                TcpOption::CONGESTION => {
                    const TCP_CONGESTION_NAME_MAX: usize = 16;
                    let data = optval
                        .to_owned_slice(TCP_CONGESTION_NAME_MAX.min(optlen))
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
                TcpOption::KEEPCNT => {
                    // smoltcp doesn't support fine-grained keep-alive probe
                    // counts. Accept and ignore the value so applications that
                    // set it (e.g., curl) don't fail.
                    let _val: u32 = super::read_from_user(optval, size_of::<u32>())?;
                }
                TcpOption::KEEPIDLE => {
                    // smoltcp uses a single keep-alive interval (set via
                    // TCP_KEEPINTVL / SO_KEEPALIVE). Accept KEEPIDLE and
                    // forward it as the keep-alive interval so the setting
                    // takes effect.
                    let val: u32 = super::read_from_user(optval, size_of::<u32>())?;
                    if val == 0 {
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
                TcpOption::INFO => {
                    return Err(Errno::EOPNOTSUPP);
                }
                TcpOption::NODELAY | TcpOption::CORK => {
                    let val: u32 = super::read_from_user(optval, size_of::<u32>())?;
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
                    let val: u32 = super::read_from_user(optval, size_of::<u32>())?;
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
        optval: MutPtr<u8>,
        len: u32,
        get_option: F,
    ) -> Result<usize, Errno>
    where
        F: FnOnce(SocketOption) -> SocketOptionValue,
    {
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
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
                    super::write_to_user(tv, optval, len)
                }
                SocketOption::REUSEADDR
                | SocketOption::REUSEPORT
                | SocketOption::KEEPALIVE
                | SocketOption::BROADCAST => {
                    let SocketOptionValue::U32(val) = get_option(sopt) else {
                        unreachable!()
                    };
                    super::write_to_user(val, optval, len)
                }
                _ => Err(Errno::ENOPROTOOPT),
            },
            _ => Err(Errno::ENOPROTOOPT),
        }
    }
    #[cfg(feature = "worker_local_inet")]
    fn getsockopt(
        &self,
        fd: &SocketFd,
        optname: SocketOptionName,
        optval: MutPtr<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        match self.getsockopt_common(optname, optval, len, |sopt| {
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            self.with_socket_options(fd, |options| match sopt {
                SocketOption::RCVTIMEO => SocketOptionValue::Timeout(options.recv_timeout),
                SocketOption::SNDTIMEO => SocketOptionValue::Timeout(options.send_timeout),
                SocketOption::LINGER => SocketOptionValue::Timeout(options.linger_timeout),
                SocketOption::REUSEADDR => SocketOptionValue::U32(u32::from(options.reuse_address)),
                SocketOption::REUSEPORT => SocketOptionValue::U32(u32::from(options.reuse_port)),
                SocketOption::KEEPALIVE => SocketOptionValue::U32(u32::from(options.keep_alive)),
                SocketOption::BROADCAST => SocketOptionValue::U32(u32::from(options.broadcast)),
                SocketOption::SNDBUF => SocketOptionValue::U32(
                    options
                        .send_buffer_size
                        .unwrap_or_else(|| litebox::net::SOCKET_BUFFER_SIZE.truncate()),
                ),
                SocketOption::RCVBUF => SocketOptionValue::U32(
                    options
                        .recv_buffer_size
                        .unwrap_or_else(|| litebox::net::SOCKET_BUFFER_SIZE.truncate()),
                ),
                _ => unreachable!(),
            })
        }) {
            Err(Errno::ENOPROTOOPT) => {} // fallthrough to handle other options
            other => return other,
        }

        let val: u32 = match optname {
            SocketOptionName::IP(ipopt) => match ipopt {
                litebox_common_linux::IpOption::TOS
                | litebox_common_linux::IpOption::RECVERR
                | litebox_common_linux::IpOption::MTU_DISCOVER
                | litebox_common_linux::IpOption::PKTINFO => return Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(sopt) => match sopt {
                // handled by `getsockopt_common`
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::REUSEPORT
                | SocketOption::KEEPALIVE
                | SocketOption::BROADCAST
                | SocketOption::RCVBUF
                | SocketOption::SNDBUF => {
                    unreachable!()
                }
                SocketOption::ERROR => {
                    // SO_ERROR is self-clearing: atomically read and reset to 0.
                    let proxy = self.get_proxy(fd)?;
                    let async_error = proxy.get_async_error(true);
                    match async_error {
                        Some(err) => {
                            let errno: Errno = err.into();
                            i32::from(errno).cast_unsigned()
                        }
                        None => 0,
                    }
                }
                SocketOption::TYPE => self.get_socket_type(fd)? as u32,
                SocketOption::RCVBUF | SocketOption::SNDBUF => {
                    litebox::net::SOCKET_BUFFER_SIZE.truncate()
                }
                SocketOption::PEERCRED => return Err(Errno::ENOPROTOOPT),
            },
            SocketOptionName::IPv6(litebox_common_linux::Ipv6Option::V6ONLY) => 0,
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
                            .write_slice_at_offset(0, &name.as_bytes()[..len])
                            .ok_or(Errno::EFAULT)?;
                        return Ok(len);
                    }
                    TcpOption::KEEPCNT => {
                        // smoltcp doesn't track probe count; return Linux
                        // default.
                        DEFAULT_TCP_KEEPCNT
                    }
                    TcpOption::KEEPIDLE => {
                        // Return the keep-alive interval as KEEPIDLE (smoltcp
                        // doesn't distinguish idle vs interval).
                        let TcpOptionData::KEEPALIVE(interval) = self
                            .net
                            .lock()
                            .get_tcp_option(fd, litebox::net::TcpOptionName::KEEPALIVE)?
                        else {
                            unreachable!()
                        };
                        interval.map_or(DEFAULT_TCP_KEEPIDLE_SECS, |d| {
                            d.as_secs().try_into().unwrap()
                        })
                    }
                    TcpOption::INFO => {
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
        super::write_to_user(val, optval, len)
    }

    #[cfg(feature = "worker_local_inet")]
    pub(super) fn try_accept(
        &self,
        fd: &SocketFd,
        peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd, TryOpError<Errno>> {
        // Drive smoltcp explicitly — platform_interaction is Manual, so
        // automated_platform_interaction inside accept() is a no-op.
        // Without this, the network thread's poll results aren't visible
        // to Network::accept() because it doesn't re-poll.
        let mut net = self.net.lock();
        let _ = net.perform_platform_interaction();
        let result = net.accept(fd, peer).map_err(|e| match e {
            AcceptError::NoConnectionsReady => TryOpError::TryAgain,
            AcceptError::InvalidFd | AcceptError::NotListening => TryOpError::Other(e.into()),
            _ => unimplemented!(),
        });
        drop(net);
        // Wake the network worker to handle follow-up transmissions
        // (SYN-ACK, ACKs for accepted connections).
        litebox_platform_multiplex::platform().wake_network_worker();
        result
    }

    #[cfg(feature = "worker_local_inet")]
    pub(super) fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd,
        mut peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd, Errno> {
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

    #[cfg(feature = "worker_local_inet")]
    fn bind(&self, fd: &SocketFd, sockaddr: SocketAddr) -> Result<(), Errno> {
        let reuse_port = self.with_socket_options(fd, |options| options.reuse_port);
        self.net
            .lock()
            .bind(fd, &sockaddr, reuse_port)
            .map_err(Errno::from)
    }

    /// Non-blocking TCP accept by raw guest fd number. Looks up the SocketFd
    /// through the FilesState fd table, then calls try_accept.
    #[cfg(feature = "worker_local_inet")]
    pub(super) fn try_accept_by_raw_fd(
        &self,
        raw_fd: u32,
        files: &core::cell::RefCell<alloc::sync::Arc<crate::syscalls::file::FilesState<FS>>>,
    ) -> Result<SocketFd, Errno> {
        files.borrow().with_socket(
            self,
            raw_fd,
            |fd| {
                self.try_accept(fd, None).map_err(|e| match e {
                    TryOpError::TryAgain => Errno::EAGAIN,
                    TryOpError::Other(e) => e,
                    TryOpError::WaitError(_) => Errno::EINTR,
                })
            },
            |_| Err(Errno::ENOTSOCK),
        )
    }

    #[cfg(feature = "worker_local_inet")]
    pub(super) fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd,
        sockaddr: SocketAddr,
    ) -> Result<(), Errno> {
        if sockaddr.port() == 0 {
            return Err(Errno::ECONNREFUSED);
        }
        // Linux treats connect(0.0.0.0:port) as connect(127.0.0.1:port).
        // Similarly, connect to the guest's own virtual interface IP
        // (10.0.0.2 in smoltcp) should be treated as loopback.
        // Apply these mappings here so the Network::connect redirect
        // (which converts loopback to the gateway) handles them correctly.
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        let sockaddr = match sockaddr {
            SocketAddr::V4(v4)
                if v4.ip().is_unspecified()
                    || *v4.ip() == core::net::Ipv4Addr::new(10, 0, 0, 2) =>
            {
                let msg = alloc::format!(
                    "SHIM CONNECT REMAP: {}:{} -> 127.0.0.1:{}\n",
                    v4.ip(),
                    v4.port(),
                    v4.port()
                );
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&msg);
                SocketAddr::V4(core::net::SocketAddrV4::new(
                    core::net::Ipv4Addr::LOCALHOST,
                    v4.port(),
                ))
            }
            other => other,
        };
        let mut check_progress = false;
        cx.wait_on_events::<_, Errno>(
            self.get_status(fd).contains(OFlags::NONBLOCK),
            Events::IN | Events::OUT,
            |observer, filter| {
                let proxy = self.get_proxy(fd)?;
                proxy.register_observer(observer, filter);
                Ok(())
            },
            || {
                // Drive smoltcp explicitly — platform_interaction is Manual, so
                // automated_platform_interaction inside connect() is a no-op.
                // Without this, the SYN packet sits in smoltcp's queue until
                // the network worker's poll timeout fires.
                let mut net = self.net.lock();
                let _ = net.perform_platform_interaction();
                let result = net.connect(fd, &sockaddr, check_progress);
                drop(net);
                // Wake the network worker to handle follow-up packets
                // (SYN-ACK processing, retransmissions).
                litebox_platform_multiplex::platform().wake_network_worker();
                match result {
                    Ok(()) => Ok(()),
                    Err(litebox::net::errors::ConnectError::InProgress) => {
                        check_progress = true;
                        Err(TryOpError::TryAgain)
                    }
                    Err(e) => Err(TryOpError::Other(e.into())),
                }
            },
        )
        .map_err(|err| match err {
            TryOpError::TryAgain => Errno::EINPROGRESS,
            TryOpError::WaitError(_) => Errno::EINTR,
            TryOpError::Other(err) => err.into(),
        })
    }

    #[cfg(feature = "worker_local_inet")]
    fn listen(&self, fd: &SocketFd, backlog: u16) -> Result<(), Errno> {
        self.net.lock().listen(fd, backlog).map_err(Errno::from)
    }

    #[cfg(feature = "worker_local_inet")]
    pub(super) fn send_listen_route_transfer(&self, port: u16) -> Result<(), Errno> {
        self.platform
            .send_port_listen_transfer(port)
            .map_err(|_| Errno::EIO)
    }

    #[cfg(feature = "worker_local_inet")]
    fn shutdown(&self, fd: &SocketFd, read: bool, write: bool) -> Result<(), Errno> {
        let result = self
            .net
            .lock()
            .shutdown(fd, read, write)
            .map_err(Errno::from);
        if result.is_ok() && write {
            // shutdown(WR) drains pending TX data into smoltcp and queues FIN;
            // in manual-interaction mode, wake the network worker so that work
            // is flushed even if the preceding send wake raced and was already
            // consumed.
            litebox_platform_multiplex::platform().wake_network_worker();
        }
        result
    }

    /// Send data via socket channel (lock-free path).
    ///
    /// This uses the channel-based approach where the user writes to a TX ring buffer,
    /// and the network worker later drains it.
    #[cfg(feature = "worker_local_inet")]
    pub(crate) fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddr>,
    ) -> Result<usize, Errno> {
        let proxy = self.get_proxy(fd)?;

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
                false,
            ) {
                match err {
                    litebox::net::errors::BindError::AlreadyBound => {
                        // Another thread bound it in the meantime - that's fine
                    }
                    litebox::net::errors::BindError::InvalidFd => return Err(Errno::EBADF),
                    litebox::net::errors::BindError::UnsupportedAddress(_)
                    | litebox::net::errors::BindError::PortAlreadyInUse(_) => unreachable!(),
                    _ => unimplemented!(),
                }
            }
            // Get the assigned port
            let local_addr = net.get_local_addr(fd).map_err(Errno::from)?;
            // If another thread already set a port, that's fine - we'll use theirs
            let _ = proxy.set_local_port(local_addr.port());
        }

        // Convert `SendFlags` to `litebox::net::SendFlags`
        // `DONTWAIT` and `NOSIGNAL` are handled in this function so we don't convert them.
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
                    Ok(n) => {
                        litebox_platform_multiplex::platform().wake_network_worker();
                        Ok(n)
                    }
                    Err(e) => Err(TryOpError::Other(Errno::from(e))),
                },
            )
            .map_err(Errno::from)
    }

    /// Receive data via socket channel (lock-free path).
    ///
    /// This uses the channel-based approach where the user reads from an RX ring buffer
    /// that the network worker populates.
    #[cfg(feature = "worker_local_inet")]
    pub(crate) fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd,
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
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            match self.get_socket_type(fd)? {
                SockType::Datagram | SockType::Raw => {
                    new_flags.insert(litebox::net::ReceiveFlags::TRUNC);
                }
                SockType::Stream => {
                    new_flags.insert(litebox::net::ReceiveFlags::DISCARD);
                }
                _ => unimplemented!(),
            }
        }

        let proxy = self.get_proxy(fd)?;
        cx.with_timeout(timeout)
            .wait_on_events(
                is_nonblock,
                Events::IN,
                |observer, filter| {
                    proxy.register_observer(observer, filter);
                    Ok(())
                },
                || {
                    // Drive smoltcp synchronously before checking the proxy ring:
                    // platform interaction is manual, and the background network
                    // worker can otherwise sleep with ACKed data still queued in
                    // smoltcp but not yet visible to this socket channel.
                    loop {
                        let advice = self.net.lock().perform_platform_interaction();
                        if !advice.call_again_immediately() {
                            break;
                        }
                    }

                    match proxy.try_read(buf, new_flags, source_addr.as_deref_mut()) {
                        Ok(0) => {
                            litebox_platform_multiplex::platform().wake_network_worker();
                            Err(TryOpError::TryAgain)
                        }
                        Ok(n) => Ok(n),
                        // Eof: peer closed the connection and all data has been
                        // consumed. Return 0 to the guest (standard EOF).
                        Err(litebox::net::errors::ReceiveError::Eof) => Ok(0),
                        Err(e) => Err(TryOpError::Other(Errno::from(e))),
                    }
                },
            )
            .map_err(Errno::from)
    }

    #[cfg(feature = "worker_local_inet")]
    fn get_socket_type(&self, fd: &SocketFd) -> Result<SockType, Errno> {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |sock_type: &SockType| *sock_type)
            .map_err(|e| match e {
                litebox::fd::MetadataError::NoSuchMetadata => Errno::ENOTSOCK,
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })
    }

    #[cfg(feature = "worker_local_inet")]
    fn get_status(&self, fd: &SocketFd) -> litebox::fs::OFlags {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |SocketOFlags(flags)| *flags)
            .unwrap()
            & litebox::fs::OFlags::STATUS_FLAGS_MASK
    }

    #[cfg(feature = "worker_local_inet")]
    pub(crate) fn get_proxy(&self, fd: &SocketFd) -> Result<Arc<NetworkProxy<Platform>>, Errno> {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |SocketProxy(proxy)| proxy.clone())
            .map_err(|e| match e {
                litebox::fd::MetadataError::NoSuchMetadata => unreachable!(),
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })
    }

    /// Look up the network proxy for a socket given its raw fd integer.
    #[cfg(feature = "worker_local_inet")]
    pub(super) fn get_proxy_by_raw_fd(
        &self,
        raw_fd: u32,
        files: &core::cell::RefCell<Arc<crate::syscalls::file::FilesState<FS>>>,
    ) -> Option<Arc<NetworkProxy<Platform>>> {
        {
            let files_ref = files.borrow();
            let rds = files_ref.raw_descriptor_store.read();
            if rds
                .fd_from_raw_integer::<crate::syscalls::broker_inet_listener::BrokerInetListenerSubsystem>(
                    raw_fd as usize,
                )
                .is_ok()
            {
                return None;
            }
        }
        files
            .borrow()
            .with_socket(
                self,
                raw_fd,
                |fd| self.get_proxy(fd).map(Some),
                |_| Ok(None),
            )
            .ok()
            .flatten()
    }

    #[cfg(feature = "worker_local_inet")]
    pub(crate) fn close_socket(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: Arc<SocketFd>,
    ) -> Result<(), Errno> {
        let linger_timeout = self.with_socket_options(&fd, |opt| opt.linger_timeout);
        let behavior = match linger_timeout {
            Some(timeout) if timeout.is_zero() => CloseBehavior::Immediate,
            Some(_) => CloseBehavior::GracefulIfNoPendingData,
            // Default (no SO_LINGER): flush pending send data before FIN.
            // Without this, a write() immediately followed by close() can
            // lose data because smoltcp sends FIN before the queued data.
            None => CloseBehavior::GracefulIfNoPendingData,
        };
        let is_nonblock = self.get_status(&fd).contains(OFlags::NONBLOCK);
        let proxy = self.get_proxy(&fd)?;
        let result = match cx.with_timeout(linger_timeout).wait_on_events(
            is_nonblock,
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
                Err(_) => unimplemented!(),
            },
        ) {
            Ok(()) => Ok(()),
            Err(TryOpError::WaitError(WaitError::TimedOut)) => self
                .net
                .lock()
                .close(&fd, CloseBehavior::Immediate)
                .map_err(Errno::from),
            Err(TryOpError::TryAgain) => {
                // close() must never return EAGAIN — the fd must be freed.
                // If GracefulIfNoPendingData returned DataPending (on a
                // non-blocking socket), fall back to Graceful which always
                // succeeds and lets smoltcp flush data in the background.
                self.net
                    .lock()
                    .close(&fd, CloseBehavior::Graceful)
                    .map_err(Errno::from)
            }
            Err(e) => Err(e.into()),
        };
        // Wake the network worker so the FIN we just queued goes out and any
        // peer connection (e.g. loopback in the same litebox instance)
        // observes the CloseWait transition promptly. Without this wake, a
        // peer process reading from the connection can block indefinitely
        // because its receive-side never sees EOF.
        litebox_platform_multiplex::platform().wake_network_worker();
        result
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

fn socket_option_name_to_raw(optname: SocketOptionName) -> (i32, i32) {
    match optname {
        SocketOptionName::IP(name) => (0, name as i32),
        SocketOptionName::IPv6(name) => (41, name as i32),
        SocketOptionName::Socket(name) => (1, name as i32),
        SocketOptionName::TCP(name) => (IPProtocol::TCP as i32, name as i32),
    }
}

/// Socket-I/O dispatch class for a raw fd. The shared, exhaustive gate that
/// every socket syscall handler routes through (via [`FilesState::run_on_raw_fd`]),
/// mirroring [`crate::syscalls::migration_policy::migration_policies_for`].
///
/// This replaces the per-handler `try_with_broker_*` probe chains — where each
/// handler independently enumerated a *different* subset of socket subsystems,
/// so a type handled in one syscall could be silently missing in a sibling (the
/// `do_sendmsg` vs `do_sendto` `tcp_conn` gap) — and the runtime
/// [`assert_no_unhandled_socket_subsystem`] safety net, with a *compile-time*
/// gate: adding a `RawFdRef` variant trips E0004 in [`socket_io_class`], and a
/// new `SocketIoClass` variant trips E0004 in every handler that matches on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SocketIoClass {
    BrokerSocketPair,
    BrokerSocketDgram,
    BrokerSocketSeqPacket,
    BrokerUnixStream,
    BrokerTcpConn,
    BrokerInetListener,
    BrokerInetDgram,
    BrokerInetRaw,
    /// Shim-local AF_UNIX socket, or (under `worker_local_inet`) the legacy
    /// smoltcp inet socket — both dispatched through [`FilesState::with_socket`].
    WithSocket,
    /// Not a socket at all (regular file, eventfd/timerfd/pidfd, epoll, broker
    /// pipe, broker pty, signalfd, inotify, host-passthrough fd) — `ENOTSOCK`.
    NotASocket,
}

/// Exhaustive classifier over `RawFdRef`; no wildcard arm (the workspace denies
/// `clippy::wildcard_enum_match_arm`). See [`SocketIoClass`].
pub(super) fn socket_io_class<FS: ShimFS>(r: &crate::RawFdRef<'_, FS>) -> SocketIoClass {
    use crate::RawFdRef;
    match r {
        RawFdRef::BrokerSocketPair(_) => SocketIoClass::BrokerSocketPair,
        RawFdRef::BrokerSocketDgram(_) => SocketIoClass::BrokerSocketDgram,
        RawFdRef::BrokerSocketSeqPacket(_) => SocketIoClass::BrokerSocketSeqPacket,
        RawFdRef::BrokerUnixStream(_) => SocketIoClass::BrokerUnixStream,
        RawFdRef::BrokerTcpConn(_) => SocketIoClass::BrokerTcpConn,
        RawFdRef::BrokerInetListener(_) => SocketIoClass::BrokerInetListener,
        RawFdRef::BrokerInetDgram(_) => SocketIoClass::BrokerInetDgram,
        RawFdRef::BrokerInetRaw(_) => SocketIoClass::BrokerInetRaw,
        RawFdRef::Unix(_) => SocketIoClass::WithSocket,
        #[cfg(feature = "worker_local_inet")]
        RawFdRef::Net(_) => SocketIoClass::WithSocket,
        RawFdRef::Fs(_)
        | RawFdRef::Eventfd(_)
        | RawFdRef::Epoll(_)
        | RawFdRef::HostPassthroughFd(_)
        | RawFdRef::BrokerPipe(_)
        | RawFdRef::BrokerPty(_)
        | RawFdRef::Signalfd(_)
        | RawFdRef::Inotify(_) => SocketIoClass::NotASocket,
    }
}

/// Why an fd reached the raw [`PassedFd`] fallthrough on the `SCM_RIGHTS`
/// send path — i.e. the send match above did not emit a broker token for it.
///
/// Duplicating the raw host fd into the receiver is only correct for a
/// genuinely kernel-/host-backed descriptor. A *broker*-backed descriptor
/// has no meaningful host fd to hand over: the duplicated fd is not
/// registered with the broker in the receiving process, so it behaves as a
/// dead handle — the node `SentHandleNotReceivedWarning` /
/// "Could not find pty N on pty host" signature. Such a type must instead be
/// made SCM-tokenizable in the send/receive match (add a `SubsystemTag` and
/// reacquire it on the receive side), not silently passed as a raw fd.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ScmPassedFdKind {
    /// Kernel-/host-backed; duplicating the raw host fd is the correct
    /// transfer (kernel inet socket, shim AF_UNIX socket, host-passthrough
    /// fd, kernel eventfd, regular file).
    KernelOrHostBacked,
    /// Broker-backed but not (yet) SCM-tokenizable. Carries the variant name
    /// so the gap is loud in the diag log instead of a silent dead handle.
    UnsupportedBrokerFd(&'static str),
}

/// Exhaustive classifier over `RawFdRef` for the `SCM_RIGHTS` send
/// fallthrough; no wildcard arm (the workspace denies
/// `clippy::wildcard_enum_match_arm`) so adding a `RawFdRef` variant trips
/// E0004 here and forces a deliberate SCM-transfer decision. See
/// [`ScmPassedFdKind`]. The broker arms that are normally tokenized in the
/// send match (pipe/socketpair/unix-stream/tcp/pty-master/inet-listener)
/// only reach this classifier on a provider-missing anomaly, which is itself
/// worth naming loudly.
fn scm_passed_fd_kind<FS: ShimFS>(r: &crate::RawFdRef<'_, FS>) -> ScmPassedFdKind {
    use crate::RawFdRef;
    use ScmPassedFdKind::{KernelOrHostBacked, UnsupportedBrokerFd};
    match r {
        RawFdRef::Fs(_) => KernelOrHostBacked,
        #[cfg(feature = "worker_local_inet")]
        RawFdRef::Net(_) => KernelOrHostBacked,
        RawFdRef::Eventfd(_) => KernelOrHostBacked,
        RawFdRef::Unix(_) => KernelOrHostBacked,
        RawFdRef::HostPassthroughFd(_) => KernelOrHostBacked,
        RawFdRef::Epoll(_) => UnsupportedBrokerFd("epoll"),
        RawFdRef::BrokerPipe(_) => UnsupportedBrokerFd("broker_pipe"),
        RawFdRef::BrokerSocketPair(_) => UnsupportedBrokerFd("broker_socketpair"),
        RawFdRef::BrokerSocketDgram(_) => UnsupportedBrokerFd("broker_socket_dgram"),
        RawFdRef::BrokerSocketSeqPacket(_) => UnsupportedBrokerFd("broker_socket_seqpacket"),
        RawFdRef::BrokerUnixStream(_) => UnsupportedBrokerFd("broker_unix_stream"),
        RawFdRef::BrokerTcpConn(_) => UnsupportedBrokerFd("broker_tcp_conn"),
        RawFdRef::BrokerPty(_) => UnsupportedBrokerFd("broker_pty"),
        RawFdRef::Signalfd(_) => UnsupportedBrokerFd("signalfd"),
        RawFdRef::Inotify(_) => UnsupportedBrokerFd("inotify"),
        RawFdRef::BrokerInetListener(_) => UnsupportedBrokerFd("broker_inet_listener"),
        RawFdRef::BrokerInetDgram(_) => UnsupportedBrokerFd("broker_inet_dgram"),
        RawFdRef::BrokerInetRaw(_) => UnsupportedBrokerFd("broker_inet_raw"),
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Classify `sockfd` for socket-I/O dispatch via the exhaustive
    /// [`socket_io_class`] gate, or `EBADF` if the fd is unknown.
    pub(super) fn socket_io_class_of(&self, sockfd: u32) -> Result<SocketIoClass, Errno> {
        self.files
            .borrow()
            .run_on_raw_fd(sockfd as usize, |r| socket_io_class(&r))
    }

    /// Returns `Some(result)` if `sockfd` is a broker socketpair fd; returns
    /// `None` so callers can fall through to the legacy `with_socket` dispatch
    /// otherwise.
    ///
    /// The closure receives the typed fd rather than an entry handle because some
    /// existing broker-socketpair socket ops only need fd classification. Write
    /// call sites obtain the entry handle inside the closure, preserving their
    /// existing `EBADF` behavior if the descriptor entry disappeared.
    fn try_with_broker_sp<R>(
        &self,
        sockfd: u32,
        op: impl FnOnce(&BrokerSocketPairTypedFd) -> Result<R, Errno>,
    ) -> Option<Result<R, Errno>> {
        let raw_fd = match usize::try_from(sockfd) {
            Ok(raw_fd) => raw_fd,
            Err(_) => return Some(Err(Errno::EBADF)),
        };
        let broker_sp = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_socketpair::BrokerSocketPairSubsystem>(raw_fd)
                .ok()
        };
        broker_sp.map(|typed| op(typed.as_ref()))
    }

    fn broker_sp_handle(
        &self,
        typed: &BrokerSocketPairTypedFd,
    ) -> Result<BrokerSocketPairHandle, Errno> {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(Errno::EBADF)
    }

    fn try_with_broker_socket_dgram<R>(
        &self,
        sockfd: u32,
        op: impl FnOnce(&BrokerSocketDgramTypedFd) -> Result<R, Errno>,
    ) -> Option<Result<R, Errno>> {
        let raw_fd = match usize::try_from(sockfd) {
            Ok(raw_fd) => raw_fd,
            Err(_) => return Some(Err(Errno::EBADF)),
        };
        let broker_dgram = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_socket_dgram::BrokerSocketDgramSubsystem>(
                    raw_fd,
                )
                .ok()
        };
        broker_dgram.map(|typed| op(typed.as_ref()))
    }

    fn broker_socket_dgram_handle(
        &self,
        typed: &BrokerSocketDgramTypedFd,
    ) -> Result<BrokerSocketDgramHandle, Errno> {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(Errno::EBADF)
    }

    fn try_with_broker_socket_seqpacket<R>(
        &self,
        sockfd: u32,
        op: impl FnOnce(&BrokerSocketSeqPacketTypedFd) -> Result<R, Errno>,
    ) -> Option<Result<R, Errno>> {
        let raw_fd = match usize::try_from(sockfd) {
            Ok(raw_fd) => raw_fd,
            Err(_) => return Some(Err(Errno::EBADF)),
        };
        let broker_seqpacket = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(
                    raw_fd,
                )
                .ok()
        };
        broker_seqpacket.map(|typed| op(typed.as_ref()))
    }

    fn broker_socket_seqpacket_handle(
        &self,
        typed: &BrokerSocketSeqPacketTypedFd,
    ) -> Result<BrokerSocketSeqPacketHandle, Errno> {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(Errno::EBADF)
    }

    fn try_with_broker_unix_stream<R>(
        &self,
        sockfd: u32,
        op: impl FnOnce(&BrokerUnixStreamTypedFd) -> Result<R, Errno>,
    ) -> Option<Result<R, Errno>> {
        let raw_fd = match usize::try_from(sockfd) {
            Ok(raw_fd) => raw_fd,
            Err(_) => return Some(Err(Errno::EBADF)),
        };
        let broker_unix_stream = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_unix_stream::BrokerUnixStreamSubsystem>(raw_fd)
                .ok()
        };
        broker_unix_stream.map(|typed| op(typed.as_ref()))
    }

    fn broker_unix_stream_handle(
        &self,
        typed: &BrokerUnixStreamTypedFd,
    ) -> Result<BrokerUnixStreamHandle, Errno> {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(Errno::EBADF)
    }

    fn try_with_broker_tcp_conn<R>(
        &self,
        sockfd: u32,
        op: impl FnOnce(&BrokerTcpConnTypedFd) -> Result<R, Errno>,
    ) -> Option<Result<R, Errno>> {
        let raw_fd = match usize::try_from(sockfd) {
            Ok(raw_fd) => raw_fd,
            Err(_) => return Some(Err(Errno::EBADF)),
        };
        let broker_tcp = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_tcp_conn::BrokerTcpConnSubsystem>(raw_fd)
                .ok()
        };
        broker_tcp.map(|typed| op(typed.as_ref()))
    }

    fn broker_tcp_conn_handle(
        &self,
        typed: &BrokerTcpConnTypedFd,
    ) -> Result<BrokerTcpConnHandle, Errno> {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(Errno::EBADF)
    }

    fn try_with_broker_inet_listener<R>(
        &self,
        sockfd: u32,
        op: impl FnOnce(&BrokerInetListenerTypedFd) -> Result<R, Errno>,
    ) -> Option<Result<R, Errno>> {
        let raw_fd = match usize::try_from(sockfd) {
            Ok(raw_fd) => raw_fd,
            Err(_) => return Some(Err(Errno::EBADF)),
        };
        let broker_listener = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_inet_listener::BrokerInetListenerSubsystem>(
                    raw_fd,
                )
                .ok()
        };
        broker_listener.map(|typed| op(typed.as_ref()))
    }

    fn broker_inet_listener_handle(
        &self,
        typed: &BrokerInetListenerTypedFd,
    ) -> Result<BrokerInetListenerHandle, Errno> {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(Errno::EBADF)
    }

    fn try_with_broker_inet_dgram<R>(
        &self,
        sockfd: u32,
        op: impl FnOnce(&BrokerInetDgramTypedFd) -> Result<R, Errno>,
    ) -> Option<Result<R, Errno>> {
        let raw_fd = match usize::try_from(sockfd) {
            Ok(raw_fd) => raw_fd,
            Err(_) => return Some(Err(Errno::EBADF)),
        };
        let broker_dgram = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<super::broker_inet_dgram::BrokerInetDgramSubsystem>(raw_fd)
                .ok()
        };
        broker_dgram.map(|typed| op(typed.as_ref()))
    }

    fn broker_inet_dgram_handle(
        &self,
        typed: &BrokerInetDgramTypedFd,
    ) -> Result<BrokerInetDgramHandle, Errno> {
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(typed)
            .ok_or(Errno::EBADF)
    }
}

impl<FS: ShimFS> Task<FS> {
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
    pub(super) fn do_socket(
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
                match ty {
                    SockType::Stream => {
                        if !matches!(protocol, IPProtocol::Default | IPProtocol::TCP) {
                            return Err(Errno::EINVAL);
                        }
                        if crate::syscalls::broker_tcp_conn::broker_inet_tcp_conn_provider_outbound_enabled()
                            && crate::syscalls::broker_inet_listener::broker_inet_listener_provider()
                                .is_none()
                            && let Some(provider) =
                                crate::syscalls::broker_tcp_conn::broker_tcp_conn_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create(0)
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let conn = crate::syscalls::broker_tcp_conn::BrokerTcpConnFd::<
                                Platform,
                            >::new(provider, handle, status);
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt
                                .insert::<crate::syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>(
                                    conn,
                                );
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                        if let Some(provider) =
                            crate::syscalls::broker_inet_listener::broker_inet_listener_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create(0)
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let listener =
                                crate::syscalls::broker_inet_listener::BrokerInetListenerFd::<
                                    Platform,
                                >::new(provider, handle, 0, status);
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt.insert::<crate::syscalls::broker_inet_listener::BrokerInetListenerSubsystem>(listener);
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                        Err(Errno::EAFNOSUPPORT)
                    }
                    SockType::Datagram => {
                        if !matches!(protocol, IPProtocol::Default | IPProtocol::UDP) {
                            return Err(Errno::EINVAL);
                        }
                        if crate::syscalls::broker_inet_dgram::broker_inet_dgram_enabled()
                            && let Some(provider) =
                                crate::syscalls::broker_inet_dgram::broker_inet_dgram_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create(0)
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let dgram = crate::syscalls::broker_inet_dgram::BrokerInetDgramFd::<
                                Platform,
                            >::new(provider, handle, status);
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt
                                .insert::<crate::syscalls::broker_inet_dgram::BrokerInetDgramSubsystem>(
                                    dgram,
                                );
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                        Err(Errno::EAFNOSUPPORT)
                    }
                    SockType::Raw => {
                        if !matches!(protocol, IPProtocol::ICMP) {
                            return Err(Errno::EPROTONOSUPPORT);
                        }
                        if let Some(provider) =
                            crate::syscalls::broker_inet_raw::broker_inet_raw_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create(0, protocol as u8)
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let raw =
                                crate::syscalls::broker_inet_raw::BrokerInetRawFd::<Platform>::new(
                                    provider,
                                    handle,
                                    0,
                                    protocol as u8,
                                    status,
                                );
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt
                                .insert::<crate::syscalls::broker_inet_raw::BrokerInetRawSubsystem>(
                                    raw,
                                );
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                        Err(Errno::EPROTONOSUPPORT)
                    }
                    SockType::SeqPacket => Err(Errno::ESOCKTNOSUPPORT),
                    _ => Err(Errno::ESOCKTNOSUPPORT),
                }?
            }
            AddressFamily::UNIX => {
                let _ = UnixProtocol::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
                match ty {
                    SockType::Datagram => {
                        let provider =
                            crate::syscalls::broker_socket_dgram::broker_socket_dgram_provider()
                                .ok_or(Errno::ENODEV)?;
                        let mut status = OFlags::empty();
                        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                        let handle = provider
                            .create()
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        let dgram = crate::syscalls::broker_socket_dgram::BrokerSocketDgramFd::<
                            Platform,
                        >::new(provider, handle, status);
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt.insert::<
                            crate::syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem,
                        >(dgram);
                        if flags.contains(SockFlags::CLOEXEC) {
                            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                            assert!(old.is_none());
                        }
                        drop(dt);
                        #[cfg(feature = "trace_syscalls")]
                        let object_id = typed.object_id().as_u64();
                        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                            let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                            Errno::EMFILE
                        })?;
                        #[cfg(feature = "trace_syscalls")]
                        if raw_fd <= 20 {
                            litebox::log_println!(
                                self.global.platform,
                                "[FD-TRACE] pid={} socket raw_fd={} object_id={} domain={:?} type={:?} flags={:?}",
                                self.pid,
                                raw_fd,
                                object_id,
                                domain,
                                ty,
                                flags,
                            );
                        }
                        return Ok(u32::try_from(raw_fd).unwrap());
                    }
                    SockType::SeqPacket => {
                        let provider = crate::syscalls::broker_socket_seqpacket::broker_socket_seqpacket_provider()
                            .ok_or(Errno::ENODEV)?;
                        let mut status = OFlags::empty();
                        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                        let handle = provider
                            .create()
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        let seqpacket =
                            crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketFd::<
                                Platform,
                            >::new(provider, handle, status);
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt.insert::<crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(seqpacket);
                        if flags.contains(SockFlags::CLOEXEC) {
                            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                            assert!(old.is_none());
                        }
                        drop(dt);
                        #[cfg(feature = "trace_syscalls")]
                        let object_id = typed.object_id().as_u64();
                        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                            let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                            Errno::EMFILE
                        })?;
                        #[cfg(feature = "trace_syscalls")]
                        if raw_fd <= 20 {
                            litebox::log_println!(
                                self.global.platform,
                                "[FD-TRACE] pid={} socket raw_fd={} object_id={} domain={:?} type={:?} flags={:?}",
                                self.pid,
                                raw_fd,
                                object_id,
                                domain,
                                ty,
                                flags,
                            );
                        }
                        return Ok(u32::try_from(raw_fd).unwrap());
                    }
                    SockType::Stream => {
                        // Proper Model: a named AF_UNIX stream socket is a
                        // first-class broker subsystem when the provider is
                        // available (the Linux default). The local
                        // `UnixSocket` path below is the no-broker fallback
                        // used by unit tests.
                        if let Some(provider) =
                            crate::syscalls::broker_unix_stream::broker_unix_stream_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create()
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let stream = crate::syscalls::broker_unix_stream::BrokerUnixStreamFd::<
                                Platform,
                            >::new(
                                provider, handle, status
                            );
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt.insert::<crate::syscalls::broker_unix_stream::BrokerUnixStreamSubsystem>(stream);
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            #[cfg(feature = "trace_syscalls")]
                            let object_id = typed.object_id().as_u64();
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            #[cfg(feature = "trace_syscalls")]
                            if raw_fd <= 20 {
                                litebox::log_println!(
                                    self.global.platform,
                                    "[FD-TRACE] pid={} socket raw_fd={} object_id={} domain={:?} type={:?} flags={:?}",
                                    self.pid,
                                    raw_fd,
                                    object_id,
                                    domain,
                                    ty,
                                    flags,
                                );
                            }
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                    }
                    #[allow(
                        clippy::wildcard_enum_match_arm,
                        reason = "SockType is non_exhaustive; unknown socket types are unsupported"
                    )]
                    SockType::Raw | _ => return Err(Errno::ESOCKTNOSUPPORT),
                }
                let socket = UnixSocket::new(ty, flags).ok_or(Errno::ESOCKTNOSUPPORT)?;
                let typed = self
                    .global
                    .litebox
                    .descriptor_table_mut()
                    .insert::<crate::syscalls::unix::UnixSocketSubsystem<FS>>(socket);
                if flags.contains(SockFlags::CLOEXEC) {
                    let old = self
                        .global
                        .litebox
                        .descriptor_table_mut()
                        .set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }

                #[cfg(feature = "trace_syscalls")]
                let object_id = typed.object_id().as_u64();
                let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                    let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                    Errno::EMFILE
                })?;
                #[cfg(feature = "trace_syscalls")]
                if raw_fd <= 20 {
                    litebox::log_println!(
                        self.global.platform,
                        "[FD-TRACE] pid={} socket raw_fd={} object_id={} domain={:?} type={:?} flags={:?}",
                        self.pid,
                        raw_fd,
                        object_id,
                        domain,
                        ty,
                        flags,
                    );
                }
                raw_fd
            }
            AddressFamily::INET6 => {
                // Map AF_INET6 to AF_INET internally. The smoltcp stack only
                // supports IPv4, but many programs (Node.js, VS Code) try IPv6
                // loopback (::1). We create an AF_INET socket and map addresses:
                //   ::1 → 127.0.0.1,  :: → 0.0.0.0
                let protocol = IPProtocol::try_from(protocol).map_err(|_| {
                    log_unsupported!("protocol = {protocol}");
                    Errno::EPROTONOSUPPORT
                })?;
                match ty {
                    SockType::Stream => {
                        if !matches!(protocol, IPProtocol::Default | IPProtocol::TCP) {
                            return Err(Errno::EINVAL);
                        }
                        if crate::syscalls::broker_tcp_conn::broker_inet_tcp_conn_provider_outbound_enabled()
                            && crate::syscalls::broker_inet_listener::broker_inet_listener_provider()
                                .is_none()
                            && let Some(provider) =
                                crate::syscalls::broker_tcp_conn::broker_tcp_conn_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create(0)
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let conn = crate::syscalls::broker_tcp_conn::BrokerTcpConnFd::<
                                Platform,
                            >::new(provider, handle, status);
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt
                                .insert::<crate::syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>(
                                    conn,
                                );
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            self.inet6_fds
                                .borrow_mut()
                                .insert(u32::try_from(raw_fd).unwrap());
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                        if let Some(provider) =
                            crate::syscalls::broker_inet_listener::broker_inet_listener_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create(1)
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let listener =
                                crate::syscalls::broker_inet_listener::BrokerInetListenerFd::<
                                    Platform,
                                >::new(provider, handle, 1, status);
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt.insert::<crate::syscalls::broker_inet_listener::BrokerInetListenerSubsystem>(listener);
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            self.inet6_fds
                                .borrow_mut()
                                .insert(u32::try_from(raw_fd).unwrap());
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                        Err(Errno::EAFNOSUPPORT)
                    }
                    SockType::Datagram => {
                        if !matches!(protocol, IPProtocol::Default | IPProtocol::UDP) {
                            return Err(Errno::EINVAL);
                        }
                        if crate::syscalls::broker_inet_dgram::broker_inet_dgram_enabled()
                            && let Some(provider) =
                                crate::syscalls::broker_inet_dgram::broker_inet_dgram_provider()
                        {
                            let mut status = OFlags::empty();
                            status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                            let handle = provider
                                .create(1)
                                .map_err(super::broker_backed::broker_err_to_errno)?;
                            let dgram = crate::syscalls::broker_inet_dgram::BrokerInetDgramFd::<
                                Platform,
                            >::new(provider, handle, status);
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed = dt
                                .insert::<crate::syscalls::broker_inet_dgram::BrokerInetDgramSubsystem>(
                                    dgram,
                                );
                            if flags.contains(SockFlags::CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            drop(dt);
                            let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
                                let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
                                Errno::EMFILE
                            })?;
                            self.inet6_fds
                                .borrow_mut()
                                .insert(u32::try_from(raw_fd).unwrap());
                            return Ok(u32::try_from(raw_fd).unwrap());
                        }
                        Err(Errno::EAFNOSUPPORT)
                    }
                    SockType::Raw => Err(Errno::EPROTONOSUPPORT),
                    SockType::SeqPacket => Err(Errno::ESOCKTNOSUPPORT),
                    _ => Err(Errno::ESOCKTNOSUPPORT),
                }?
            }
            AddressFamily::NETLINK => {
                // Reserve an fd number with a BrokerPipe whose write end is
                // closed immediately — all I/O is intercepted via
                // `netlink_sockets` before reaching the underlying pipe.
                // Using BrokerPipe rather than the legacy local
                // `litebox::pipes::Pipes` removes one of the few remaining
                // legacy-pipe producers; see session-state
                // `files/legacy-pipes-migration.md` (Phase 1).
                let provider = super::broker_pipe::broker_pipe_provider().ok_or(Errno::ENODEV)?;
                let (read_handle, write_handle) = provider
                    .create_pipe(4096, 4096)
                    .map_err(|_| Errno::ENODEV)?;
                provider.release(write_handle);
                let reader_entry = super::broker_pipe::BrokerPipeFd::<crate::Platform>::new(
                    alloc::sync::Arc::clone(&provider),
                    read_handle,
                    litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read,
                    OFlags::empty(),
                    0, // creation_site: sys_pipe2-equivalent (netlink sentinel)
                );
                let mut dt = self.global.litebox.descriptor_table_mut();
                let reader = dt.insert::<super::broker_pipe::BrokerPipeSubsystem>(reader_entry);
                if flags.contains(SockFlags::CLOEXEC) {
                    let old = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }
                drop(dt);
                let raw_fd = files.insert_raw_fd(reader).map_err(|reader| {
                    // Best-effort close — Broker tracks refcount; on Drop
                    // BrokerPipeFd::on_close fires `release(handle)`.
                    let _ = self.global.litebox.descriptor_table_mut().remove(&reader);
                    Errno::EMFILE
                })?;
                let fd_u32 = u32::try_from(raw_fd).unwrap();
                let mut nl = super::netlink::NetlinkRouteSocket::new();
                nl.set_nl_pid(u32::try_from(self.pid).unwrap_or(0));
                self.netlink_sockets.borrow_mut().insert(fd_u32, nl);
                raw_fd
            }
            _ => unimplemented!(),
        };
        Ok(u32::try_from(file).unwrap())
    }

    pub(crate) fn sys_socketpair(
        &self,
        domain: u32,
        type_and_flags: u32,
        protocol: u8,
        sockvec: MutPtr<u32>,
    ) -> Result<(), Errno> {
        let (ty, flags) = parse_type_and_flags(type_and_flags)?;
        let domain = AddressFamily::try_from(domain).map_err(|_| {
            log_unsupported!("socket(domain = {domain})");
            Errno::EINVAL
        })?;
        let (sock1, sock2) = self.do_socketpair(domain, ty, flags, protocol)?;
        sockvec.write_at_offset(0, sock1).ok_or(Errno::EFAULT)?;
        sockvec.write_at_offset(1, sock2).ok_or(Errno::EFAULT)?;
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

                match ty {
                    SockType::Stream => {
                        use litebox::fs::OFlags;
                        use litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint;

                        let provider =
                            crate::syscalls::broker_socketpair::broker_socketpair_provider()
                                .ok_or(Errno::ENODEV)?;
                        const SP_CAPACITY: u64 = 64 * 1024;
                        const SP_ATOMIC: u64 = 4096;
                        let (handle_a, handle_b) = provider
                            .create_socketpair(SP_CAPACITY, SP_ATOMIC)
                            .map_err(|_| Errno::EIO)?;
                        let nonblock = if flags.contains(SockFlags::NONBLOCK) {
                            OFlags::NONBLOCK
                        } else {
                            OFlags::empty()
                        };
                        let sp_a = crate::syscalls::broker_socketpair::BrokerSocketPairFd::<
                            crate::Platform,
                        >::new(
                            alloc::sync::Arc::clone(&provider),
                            handle_a,
                            BrokerSocketPairEndpoint::A,
                            nonblock,
                        );
                        let sp_b = crate::syscalls::broker_socketpair::BrokerSocketPairFd::<
                            crate::Platform,
                        >::new(
                            provider, handle_b, BrokerSocketPairEndpoint::B, nonblock
                        );
                        let files = self.files.borrow();
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed1 = dt.insert::<
                            crate::syscalls::broker_socketpair::BrokerSocketPairSubsystem,
                        >(sp_a);
                        let typed2 = dt.insert::<
                            crate::syscalls::broker_socketpair::BrokerSocketPairSubsystem,
                        >(sp_b);
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
                    SockType::SeqPacket => {
                        use litebox::fs::OFlags;

                        let provider = crate::syscalls::broker_socket_seqpacket::broker_socket_seqpacket_provider()
                            .ok_or(Errno::ENODEV)?;
                        let (handle_a, handle_b) = provider
                            .create_socketpair()
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        let mut status = OFlags::empty();
                        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                        let sp_a =
                            crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketFd::<
                                crate::Platform,
                            >::new(
                                alloc::sync::Arc::clone(&provider), handle_a, status
                            );
                        let sp_b =
                            crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketFd::<
                                crate::Platform,
                            >::new(provider, handle_b, status);
                        let files = self.files.borrow();
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed1 = dt.insert::<crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(sp_a);
                        let typed2 = dt.insert::<crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem>(sp_b);
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
                    #[cfg(test)]
                    SockType::Datagram => {
                        use core::sync::atomic::{AtomicU64, Ordering};
                        use litebox::fs::OFlags;

                        static NEXT_TEST_DGRAM_PAIR: AtomicU64 = AtomicU64::new(1);

                        let provider =
                            crate::syscalls::broker_socket_dgram::broker_socket_dgram_provider()
                                .ok_or(Errno::ENODEV)?;
                        let handle_a = provider
                            .create()
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        let handle_b = provider
                            .create()
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        let pair_id = NEXT_TEST_DGRAM_PAIR.fetch_add(1, Ordering::Relaxed);
                        let addr_a = UnixSocketAddr::Abstract(
                            alloc::format!("test-dgram-pair-{pair_id}-a").into(),
                        );
                        let addr_b = UnixSocketAddr::Abstract(
                            alloc::format!("test-dgram-pair-{pair_id}-b").into(),
                        );
                        let raw_a = crate::syscalls::broker_socket_dgram::encode_unix_addr(&addr_a);
                        let raw_b = crate::syscalls::broker_socket_dgram::encode_unix_addr(&addr_b);
                        provider
                            .bind(handle_a, &raw_a)
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        provider
                            .bind(handle_b, &raw_b)
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        provider
                            .connect(handle_a, &raw_b)
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        provider
                            .connect(handle_b, &raw_a)
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        let mut status = OFlags::empty();
                        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                        let dgram_a = crate::syscalls::broker_socket_dgram::BrokerSocketDgramFd::<
                            crate::Platform,
                        >::new(
                            alloc::sync::Arc::clone(&provider), handle_a, status
                        );
                        let dgram_b = crate::syscalls::broker_socket_dgram::BrokerSocketDgramFd::<
                            crate::Platform,
                        >::new(provider, handle_b, status);
                        let files = self.files.borrow();
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed1 = dt.insert::<crate::syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem>(dgram_a);
                        let typed2 = dt.insert::<crate::syscalls::broker_socket_dgram::BrokerSocketDgramSubsystem>(dgram_b);
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
                    _ => return Err(Errno::ESOCKTNOSUPPORT),
                }
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
pub(crate) fn read_sockaddr_from_user(
    sockaddr: ConstPtr<u8>,
    addrlen: usize,
) -> Result<SocketAddress, Errno> {
    if addrlen < 2 {
        return Err(Errno::EINVAL);
    }

    let ptr: ConstPtr<u16> = ConstPtr::from_usize(sockaddr.as_usize());
    let family = ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
    let family = AddressFamily::try_from(u32::from(family)).map_err(|_| Errno::EAFNOSUPPORT)?;
    match family {
        AddressFamily::INET => {
            if addrlen < size_of::<CSockInetAddr>() {
                return Err(Errno::EINVAL);
            }
            let ptr: ConstPtr<CSockInetAddr> = ConstPtr::from_usize(sockaddr.as_usize());
            // Note it reads the first 2 bytes (i.e., sa_family) again, but it is not used.
            // SocketAddrV4 only needs the port and addr.
            let inet_addr = ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;
            Ok(SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::from(
                inet_addr,
            ))))
        }
        AddressFamily::UNIX => {
            let path = sockaddr.to_owned_slice(addrlen).ok_or(Errno::EFAULT)?;
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
        AddressFamily::NETLINK => {
            // Netlink sockaddr — return as unnamed Unix address.
            // The actual handling is done at the syscall level.
            Ok(SocketAddress::default())
        }
        AddressFamily::INET6 => {
            if addrlen < 28 {
                return Err(Errno::EINVAL);
            }
            let raw = sockaddr.to_owned_slice(28).ok_or(Errno::EFAULT)?;
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let flowinfo = u32::from_ne_bytes(raw[4..8].try_into().unwrap());
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&raw[8..24]);
            let scope_id = u32::from_ne_bytes(raw[24..28].try_into().unwrap());
            Ok(SocketAddress::Inet(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr),
                port,
                flowinfo,
                scope_id,
            ))))
        }
        _ => todo!("unsupported family {family:?}"),
    }
}

fn socket_address_to_inet_listener_wire(sockaddr: SocketAddress) -> Result<[u8; 28], Errno> {
    match sockaddr {
        SocketAddress::Inet(SocketAddr::V4(v4)) => {
            let mut raw = [0u8; 28];
            raw[0..2].copy_from_slice(&(AddressFamily::INET as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&v4.port().to_be_bytes());
            raw[4..8].copy_from_slice(&v4.ip().octets());
            Ok(raw)
        }
        SocketAddress::Inet(SocketAddr::V6(v6)) => {
            let mut raw = [0u8; 28];
            raw[0..2].copy_from_slice(&(AddressFamily::INET6 as u16).to_ne_bytes());
            raw[2..4].copy_from_slice(&v6.port().to_be_bytes());
            raw[4..8].copy_from_slice(&v6.flowinfo().to_ne_bytes());
            raw[8..24].copy_from_slice(&v6.ip().octets());
            raw[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            Ok(raw)
        }
        SocketAddress::Unix(_) => Err(Errno::EAFNOSUPPORT),
    }
}

fn inet_listener_wire_to_socket_address(raw: [u8; 28]) -> Result<SocketAddress, Errno> {
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as u32;
    match family {
        family if family == AddressFamily::INET as u32 => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
            Ok(SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::new(
                ip, port,
            ))))
        }
        family if family == AddressFamily::INET6 as u32 => {
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let flowinfo = u32::from_ne_bytes(raw[4..8].try_into().unwrap());
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&raw[8..24]);
            let scope_id = u32::from_ne_bytes(raw[24..28].try_into().unwrap());
            Ok(SocketAddress::Inet(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr),
                port,
                flowinfo,
                scope_id,
            ))))
        }
        _ => Err(Errno::EAFNOSUPPORT),
    }
}

pub(crate) fn write_sockaddr_to_user(
    sock_addr: SocketAddress,
    addr: crate::MutPtr<u8>,
    addrlen: crate::MutPtr<u32>,
) -> Result<(), Errno> {
    let addrlen_val = addrlen.read_at_offset(0).ok_or(Errno::EFAULT)?;
    if addrlen_val >= i32::MAX as u32 {
        return Err(Errno::EINVAL);
    }
    let len: u32 = match sock_addr {
        SocketAddress::Inet(SocketAddr::V4(v4_addr)) => {
            let addrlen_val = size_of::<CSockInetAddr>().min(addrlen_val as usize);
            let c_addr: CSockInetAddr = v4_addr.into();
            let bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    (&raw const c_addr).cast::<u8>(),
                    size_of::<CSockInetAddr>(),
                )
            };
            addr.write_slice_at_offset(0, &bytes[..addrlen_val])
                .ok_or(Errno::EFAULT)?;
            size_of::<CSockInetAddr>()
        }
        SocketAddress::Unix(v) => {
            let family_ptr = MutPtr::<u16>::from_usize(addr.as_usize());
            family_ptr
                .write_at_offset(0, AddressFamily::UNIX as u16)
                .ok_or(Errno::EFAULT)?;
            match v {
                UnixSocketAddr::Unnamed => {
                    // only write family
                    size_of::<u16>()
                }
                UnixSocketAddr::Abstract(name) => {
                    let offset = offset_of!(CSockUnixAddr, path);
                    if addrlen_val as usize > offset {
                        addr.write_at_offset(isize::try_from(offset).unwrap(), 0)
                            .ok_or(Errno::EFAULT)?;
                        let max_len = addrlen_val as usize - offset - 1;
                        addr.write_slice_at_offset(
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
                    addr.write_slice_at_offset(isize::try_from(offset).unwrap(), name)
                        .ok_or(Errno::EFAULT)?;
                    let null_offset = offset + name.len();
                    // write null terminator if there is space
                    if addrlen_val as usize > null_offset {
                        addr.write_at_offset(isize::try_from(null_offset).unwrap(), 0)
                            .ok_or(Errno::EFAULT)?;
                    }
                    offset + path.len() + 1
                }
            }
        }
        SocketAddress::Inet(SocketAddr::V6(v6_addr)) => {
            let mut sa6 = [0u8; 28];
            sa6[0..2].copy_from_slice(&(AddressFamily::INET6 as u16).to_ne_bytes());
            sa6[2..4].copy_from_slice(&v6_addr.port().to_be_bytes());
            sa6[4..8].copy_from_slice(&v6_addr.flowinfo().to_ne_bytes());
            sa6[8..24].copy_from_slice(&v6_addr.ip().octets());
            sa6[24..28].copy_from_slice(&v6_addr.scope_id().to_ne_bytes());
            let copy_len = (addrlen_val as usize).min(28);
            addr.write_slice_at_offset(0, &sa6[..copy_len])
                .ok_or(Errno::EFAULT)?;
            28
        }
    }
    .truncate();
    addrlen.write_at_offset(0, len).ok_or(Errno::EFAULT)
}

/// Write a `sockaddr_in6` with a v4-mapped IPv6 address to user memory.
///
/// Converts an IPv4 `SocketAddress::Inet(V4)` to a `sockaddr_in6` with
/// address `::ffff:x.x.x.x`. This is needed for sockets created as
/// AF_INET6 that were internally mapped to AF_INET by the shim.
fn write_sockaddr_v6_mapped_to_user(
    sock_addr: SocketAddress,
    addr: crate::MutPtr<u8>,
    addrlen: crate::MutPtr<u32>,
) -> Result<(), Errno> {
    let addrlen_val = addrlen.read_at_offset(0).ok_or(Errno::EFAULT)?;
    // reason: unsupported variants intentionally share this fallback path.
    #[allow(clippy::wildcard_enum_match_arm)]
    match sock_addr {
        SocketAddress::Inet(SocketAddr::V4(v4_addr)) => {
            // struct sockaddr_in6 = 28 bytes
            let mut sa6 = [0u8; 28];
            // sin6_family = AF_INET6 (10)
            sa6[0..2].copy_from_slice(&10u16.to_ne_bytes());
            // sin6_port (network byte order)
            sa6[2..4].copy_from_slice(&v4_addr.port().to_be_bytes());
            // sin6_flowinfo = 0 (bytes 4-7, already zero)
            // sin6_addr: v4-mapped IPv6 = ::ffff:x.x.x.x (bytes 8-23)
            // First 10 bytes zero, then 2 bytes 0xff, then 4 bytes IPv4
            sa6[18] = 0xff;
            sa6[19] = 0xff;
            sa6[20..24].copy_from_slice(&v4_addr.ip().octets());
            // sin6_scope_id = 0 (bytes 24-27, already zero)

            let copy_len = (addrlen_val as usize).min(28);
            addr.write_slice_at_offset(0, &sa6[..copy_len])
                .ok_or(Errno::EFAULT)?;
            addrlen.write_at_offset(0, 28u32).ok_or(Errno::EFAULT)
        }
        other => write_sockaddr_to_user(other, addr, addrlen),
    }
}

impl<FS: ShimFS> Task<FS> {
    /// Handle syscall `accept`
    pub(crate) fn sys_accept(
        &self,
        sockfd: i32,
        addr: Option<MutPtr<u8>>,
        addrlen: Option<MutPtr<u32>>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let is_inet6 = self.inet6_fds.borrow().contains(&sockfd);
        let mut remote_addr = addr.is_some().then(SocketAddress::default);
        let fd = self.do_accept(sockfd, remote_addr.as_mut(), flags)?;
        // Accepted fds on AF_INET6 listeners should also be marked AF_INET6.
        if is_inet6 {
            self.inet6_fds.borrow_mut().insert(fd);
        }
        if let (Some(addr), Some(remote_addr)) = (addr, remote_addr) {
            let addrlen = addrlen.ok_or(Errno::EFAULT)?;
            let write_result = if is_inet6 {
                write_sockaddr_v6_mapped_to_user(remote_addr, addr, addrlen)
            } else {
                write_sockaddr_to_user(remote_addr, addr, addrlen)
            };
            if let Err(err) = write_result {
                self.sys_close(i32::try_from(fd).unwrap())
                    .expect("close a newly-accepted socket failed");
                return Err(err);
            }
        }
        Ok(fd)
    }
    #[cfg(feature = "worker_local_inet")]
    fn try_install_broker_tcp_accept(
        &self,
        accepted_file: &SocketFd,
        peer_addr: Option<&SocketAddress>,
        flags: SockFlags,
        files: &crate::syscalls::file::FilesState<FS>,
    ) -> Result<Option<usize>, Errno> {
        if !crate::syscalls::broker_tcp_conn::broker_tcp_conn_accept_enabled() {
            return Ok(None);
        }
        let peer_addr = match peer_addr.cloned() {
            Some(addr) => Some(addr),
            None => self
                .global
                .net
                .lock()
                .get_remote_addr(accepted_file)
                .ok()
                .map(SocketAddress::Inet),
        };
        let Some(SocketAddress::Inet(SocketAddr::V4(peer))) = peer_addr else {
            return Ok(None);
        };
        if peer.port() == 0 {
            return Ok(None);
        }
        let handle_id = u64::from(peer.port());
        let Some(provider) = crate::syscalls::broker_tcp_conn::broker_tcp_conn_provider() else {
            return Ok(None);
        };
        if provider.poll_tcp_conn_events(handle_id).is_err() {
            return Ok(None);
        }

        let _ = self
            .global
            .net
            .lock()
            .close(accepted_file, CloseBehavior::Immediate);
        let status = if flags.contains(SockFlags::NONBLOCK) {
            OFlags::NONBLOCK
        } else {
            OFlags::empty()
        };
        let tcp_fd = crate::syscalls::broker_tcp_conn::BrokerTcpConnFd::<Platform>::new(
            provider, handle_id, status,
        );
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<crate::syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>(tcp_fd);
        if flags.contains(SockFlags::CLOEXEC) {
            let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
            assert!(old.is_none());
        }
        drop(dt);
        let raw_fd = files.insert_raw_fd(typed).map_err(|typed| {
            let _ = self.global.litebox.descriptor_table_mut().remove(&typed);
            Errno::EMFILE
        })?;
        Ok(Some(raw_fd))
    }

    pub(super) fn do_accept(
        &self,
        sockfd: u32,
        peer: Option<&mut SocketAddress>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let class = self.socket_io_class_of(sockfd)?;
        let (fd, peer_addr) = match class {
            SocketIoClass::BrokerInetListener => self
                .try_with_broker_inet_listener(sockfd, |typed| {
                    let handle = self.broker_inet_listener_handle(typed)?;
                    let (conn_handle, peer_raw) =
                        handle.with_entry(|entry| entry.accept(&self.wait_cx()))?;
                    let tcp_provider = crate::syscalls::broker_tcp_conn::broker_tcp_conn_provider()
                        .ok_or(Errno::EIO)?;
                    let mut status = OFlags::empty();
                    status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                    let tcp_fd = crate::syscalls::broker_tcp_conn::BrokerTcpConnFd::<Platform>::new(
                        tcp_provider,
                        conn_handle,
                        status,
                    );
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    let typed_tcp = dt
                        .insert::<crate::syscalls::broker_tcp_conn::BrokerTcpConnSubsystem>(tcp_fd);
                    if flags.contains(SockFlags::CLOEXEC) {
                        let old = dt.set_fd_metadata(&typed_tcp, FileDescriptorFlags::FD_CLOEXEC);
                        assert!(old.is_none());
                    }
                    drop(dt);
                    let files = self.files.borrow();
                    let raw_fd = files.insert_raw_fd(typed_tcp).map_err(|typed_tcp| {
                        let _ = self
                            .global
                            .litebox
                            .descriptor_table_mut()
                            .remove(&typed_tcp);
                        Errno::EMFILE
                    })?;
                    Ok((
                        u32::try_from(raw_fd).unwrap(),
                        Some(inet_listener_wire_to_socket_address(peer_raw)?),
                    ))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |typed| {
                    let handle = self.broker_unix_stream_handle(typed)?;
                    let accepted_handle =
                        handle.with_entry(|entry| entry.accept(&self.wait_cx()))?;
                    let provider =
                        crate::syscalls::broker_unix_stream::broker_unix_stream_provider()
                            .ok_or(Errno::EIO)?;
                    let mut status = OFlags::empty();
                    status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                    let stream =
                        crate::syscalls::broker_unix_stream::BrokerUnixStreamFd::<Platform>::new(
                            provider,
                            accepted_handle,
                            status,
                        );
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    let typed_stream = dt.insert::<
                        crate::syscalls::broker_unix_stream::BrokerUnixStreamSubsystem,
                    >(stream);
                    if flags.contains(SockFlags::CLOEXEC) {
                        let old =
                            dt.set_fd_metadata(&typed_stream, FileDescriptorFlags::FD_CLOEXEC);
                        assert!(old.is_none());
                    }
                    drop(dt);
                    let files = self.files.borrow();
                    let raw_fd = files.insert_raw_fd(typed_stream).map_err(|typed_stream| {
                        let _ = self
                            .global
                            .litebox
                            .descriptor_table_mut()
                            .remove(&typed_stream);
                        Errno::EMFILE
                    })?;
                    Ok(u32::try_from(raw_fd).unwrap())
                })
                .unwrap_or(Err(Errno::EBADF))
                .map(|fd| (fd, Some(SocketAddress::Unix(UnixSocketAddr::Unnamed)))),
            SocketIoClass::BrokerSocketSeqPacket => self
                .try_with_broker_socket_seqpacket(sockfd, |typed| {
                    let handle = self.broker_socket_seqpacket_handle(typed)?;
                    let accepted_handle =
                        handle.with_entry(|entry| entry.accept(&self.wait_cx()))?;
                    let provider =
                        crate::syscalls::broker_socket_seqpacket::broker_socket_seqpacket_provider(
                        )
                        .ok_or(Errno::EIO)?;
                    let mut status = OFlags::empty();
                    status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
                    let seqpacket =
                        crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketFd::<
                            Platform,
                        >::new(provider, accepted_handle, status);
                    let mut dt = self.global.litebox.descriptor_table_mut();
                    let typed_seq = dt.insert::<
                        crate::syscalls::broker_socket_seqpacket::BrokerSocketSeqPacketSubsystem,
                    >(seqpacket);
                    if flags.contains(SockFlags::CLOEXEC) {
                        let old = dt.set_fd_metadata(&typed_seq, FileDescriptorFlags::FD_CLOEXEC);
                        assert!(old.is_none());
                    }
                    drop(dt);
                    let files = self.files.borrow();
                    let raw_fd = files.insert_raw_fd(typed_seq).map_err(|typed_seq| {
                        let _ = self
                            .global
                            .litebox
                            .descriptor_table_mut()
                            .remove(&typed_seq);
                        Errno::EMFILE
                    })?;
                    Ok(u32::try_from(raw_fd).unwrap())
                })
                .unwrap_or(Err(Errno::EBADF))
                .map(|fd| (fd, None)),
            SocketIoClass::BrokerSocketPair
            | SocketIoClass::BrokerSocketDgram
            | SocketIoClass::BrokerTcpConn
            | SocketIoClass::BrokerInetDgram
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => {
                let files = self.files.borrow();
                let want_peer = peer.is_some();
                let (file, peer_addr) = files.with_socket(
                    &self.global,
                    sockfd,
                    |fd| {
                        #[cfg(feature = "worker_local_inet")]
                        {
                            let sock_type = self.global.get_socket_type(fd)?;
                            let mut socket_addr = want_peer.then(|| {
                                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
                            });
                            let accepted_file =
                                self.global
                                    .accept(&self.wait_cx(), fd, socket_addr.as_mut())?;
                            let peer_addr = socket_addr.map(SocketAddress::Inet);

                            if let Some(raw_fd) = self.try_install_broker_tcp_accept(
                                &accepted_file,
                                peer_addr.as_ref(),
                                flags,
                                files.as_ref(),
                            )? {
                                return Ok((raw_fd, peer_addr));
                            }

                            let proxy =
                                self.global
                                    .initialize_socket(&accepted_file, sock_type, flags);
                            proxy.set_state(SocketState::Connected);
                            let Ok(raw_fd) = files.insert_raw_fd(accepted_file) else {
                                unimplemented!()
                            };
                            Ok((raw_fd, peer_addr))
                        }
                        #[cfg(not(feature = "worker_local_inet"))]
                        {
                            let _ = fd;
                            Err(Errno::ENOTSOCK)
                        }
                    },
                    |file| {
                        let mut socket_addr = want_peer.then_some(UnixSocketAddr::Unnamed);
                        let accepted_file =
                            file.accept(Some(self), &self.wait_cx(), flags, socket_addr.as_mut())?;
                        let peer_addr = socket_addr.map(SocketAddress::Unix);
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt.insert::<crate::syscalls::unix::UnixSocketSubsystem<FS>>(
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
                Ok((u32::try_from(file).unwrap(), peer_addr))
            }
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        }?;

        if let (Some(peer), Some(addr)) = (peer, peer_addr) {
            *peer = addr;
        }

        Ok(fd)
    }

    /// Handle syscall `connect`
    pub(crate) fn sys_connect(
        &self,
        fd: i32,
        sockaddr: ConstPtr<u8>,
        addrlen: usize,
    ) -> Result<(), Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = read_sockaddr_from_user(sockaddr, addrlen)?;
        self.do_connect(fd, sockaddr)
    }
    pub(super) fn do_connect(&self, sockfd: u32, sockaddr: SocketAddress) -> Result<(), Errno> {
        // Linux treats connect(0.0.0.0:port) as connect(127.0.0.1:port).
        // Similarly, connect to the guest's own virtual interface IP
        // (10.0.0.2) should be treated as loopback so the broker-held
        // TCP path reaches the broker's actual host listener bound on
        // 0.0.0.0:port. Apply this remap up-front so both the broker-
        // backed paths (BrokerTcpConn / BrokerInetListener) and the
        // remaining worker-local fallback see the resolved address.
        // (The old worker-local path also did this remap at line ~957;
        // duplicate here so broker paths benefit too.)
        let sockaddr = if let SocketAddress::Inet(SocketAddr::V4(v4)) = &sockaddr {
            if v4.ip().is_unspecified() || *v4.ip() == core::net::Ipv4Addr::new(10, 0, 0, 2) {
                SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
                    core::net::Ipv4Addr::LOCALHOST,
                    v4.port(),
                )))
            } else {
                sockaddr
            }
        } else {
            sockaddr
        };
        let class = self.socket_io_class_of(sockfd)?;
        match class {
            SocketIoClass::BrokerTcpConn => self
                .try_with_broker_tcp_conn(sockfd, |typed| {
                    let raw = socket_address_to_inet_listener_wire(sockaddr.clone())?;
                    let handle = self.broker_tcp_conn_handle(typed)?;
                    handle.with_entry(|entry| entry.connect(&self.wait_cx(), &raw))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetListener => self
                .try_with_broker_inet_listener(sockfd, |typed| {
                    let addr = sockaddr.clone().inet().ok_or(Errno::EAFNOSUPPORT)?;
                    let SocketAddr::V4(addr) = addr else {
                        return Err(Errno::EAFNOSUPPORT);
                    };
                    let raw_fd = usize::try_from(sockfd).map_err(|_| Errno::EBADF)?;
                    if crate::syscalls::broker_tcp_conn::broker_inet_tcp_conn_provider_outbound_enabled()
                        && let Some(tcp_provider) =
                            crate::syscalls::broker_tcp_conn::broker_tcp_conn_provider()
                    {
                        let fd_flags = self
                            .global
                            .litebox
                            .descriptor_table()
                            .with_metadata(typed, |flags: &FileDescriptorFlags| *flags)
                            .unwrap_or_else(|_| FileDescriptorFlags::empty());
                        let listener_handle = self.broker_inet_listener_handle(typed)?;
                        let (status, family) =
                            listener_handle.with_entry(|entry| (entry.get_status(), entry.family()));
                        let tcp_handle = tcp_provider
                            .create(family)
                            .map_err(super::broker_backed::broker_err_to_errno)?;
                        let tcp_fd =
                            crate::syscalls::broker_tcp_conn::BrokerTcpConnFd::<Platform>::new(
                                tcp_provider,
                                tcp_handle,
                                status,
                            );
                        let typed_tcp = {
                            let mut dt = self.global.litebox.descriptor_table_mut();
                            let typed_tcp = dt.insert::<
                                crate::syscalls::broker_tcp_conn::BrokerTcpConnSubsystem,
                            >(tcp_fd);
                            if fd_flags.contains(FileDescriptorFlags::FD_CLOEXEC) {
                                let old =
                                    dt.set_fd_metadata(&typed_tcp, FileDescriptorFlags::FD_CLOEXEC);
                                assert!(old.is_none());
                            }
                            typed_tcp
                        };
                        let tcp_handle = self.broker_tcp_conn_handle(&typed_tcp)?;
                        {
                            let files = self.files.borrow();
                            let mut rds = files.raw_descriptor_store.write();
                            let _old_fd = rds
                                .fd_consume_raw_integer::<
                                    super::broker_inet_listener::BrokerInetListenerSubsystem,
                                >(raw_fd)
                                .map_err(|_| Errno::EBADF)?;
                            assert!(rds.fd_into_specific_raw_integer(typed_tcp, raw_fd));
                        }
                        let _ = self.global.litebox.descriptor_table_mut().remove(typed);
                        let raw = socket_address_to_inet_listener_wire(SocketAddress::Inet(
                            SocketAddr::V4(addr),
                        ))?;
                        return tcp_handle.with_entry(|entry| entry.connect(&self.wait_cx(), &raw));
                    }
                    // Broker-held outbound TCP is mandatory in the linux_userland runner
                    // (`broker_inet_tcp_enabled()` is always true), so do not resurrect
                    // the old raw host-socket passthrough fallback. A host socket here
                    // would have no broker state to duplicate across cross-binary-type
                    // fork; missing provider setup is a runner configuration error.
                    Err(Errno::ENODEV)
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetDgram => self
                .try_with_broker_inet_dgram(sockfd, |typed| {
                    let raw = socket_address_to_inet_listener_wire(sockaddr.clone())?;
                    let handle = self.broker_inet_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.connect(&raw))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketDgram => self
                .try_with_broker_socket_dgram(sockfd, |typed| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    let handle = self.broker_socket_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.connect(addr))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |typed| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    let handle = self.broker_unix_stream_handle(typed)?;
                    handle.with_entry(|entry| entry.connect(addr))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketSeqPacket => self
                .try_with_broker_socket_seqpacket(sockfd, |typed| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    let handle = self.broker_socket_seqpacket_handle(typed)?;
                    handle.with_entry(|entry| entry.connect(addr))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketPair
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => self.files.borrow().with_socket(
                &self.global,
                sockfd,
                |fd| {
                    #[cfg(feature = "worker_local_inet")]
                    {
                        let addr = sockaddr.clone().inet().ok_or(Errno::EAFNOSUPPORT)?;
                        self.global.connect(&self.wait_cx(), fd, addr)
                    }
                    #[cfg(not(feature = "worker_local_inet"))]
                    {
                        let _ = fd;
                        Err(Errno::ENOTSOCK)
                    }
                },
                |file| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    file.connect(self, addr)
                },
            ),
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `bind`
    pub(crate) fn sys_bind(
        &self,
        sockfd: i32,
        sockaddr: ConstPtr<u8>,
        addrlen: usize,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = read_sockaddr_from_user(sockaddr, addrlen)?;
        self.do_bind(sockfd, sockaddr)
    }
    pub(super) fn do_bind(&self, sockfd: u32, sockaddr: SocketAddress) -> Result<(), Errno> {
        // Netlink socket: bind is a no-op.
        if self.netlink_sockets.borrow().contains_key(&sockfd) {
            self.netlink_sockets
                .borrow_mut()
                .get_mut(&sockfd)
                .unwrap()
                .bind();
            return Ok(());
        }
        let class = self.socket_io_class_of(sockfd)?;
        match class {
            SocketIoClass::BrokerTcpConn => self
                .try_with_broker_tcp_conn(sockfd, |typed| {
                    let raw = socket_address_to_inet_listener_wire(sockaddr.clone())?;
                    let listener_provider =
                        crate::syscalls::broker_inet_listener::broker_inet_listener_provider()
                            .ok_or(Errno::EINVAL)?;
                    let raw_fd = usize::try_from(sockfd).map_err(|_| Errno::EBADF)?;
                    let tcp_handle = self.broker_tcp_conn_handle(typed)?;
                    let status = tcp_handle.with_entry(|entry| entry.get_status());
                    let fd_flags = self
                        .global
                        .litebox
                        .descriptor_table()
                        .with_metadata(typed, |flags: &FileDescriptorFlags| *flags)
                        .unwrap_or_else(|_| FileDescriptorFlags::empty());
                    let listener_family = match sockaddr {
                        SocketAddress::Inet(SocketAddr::V4(_)) => 0,
                        SocketAddress::Inet(SocketAddr::V6(_)) => 1,
                        SocketAddress::Unix(_) => return Err(Errno::EAFNOSUPPORT),
                    };
                    let listener_handle = listener_provider
                        .create(listener_family)
                        .map_err(super::broker_backed::broker_err_to_errno)?;
                    let listener = crate::syscalls::broker_inet_listener::BrokerInetListenerFd::<
                        Platform,
                    >::new(
                        listener_provider, listener_handle, listener_family, status
                    );
                    listener.bind(&raw)?;
                    let typed_listener = {
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed_listener = dt.insert::<
                            crate::syscalls::broker_inet_listener::BrokerInetListenerSubsystem,
                        >(listener);
                        if fd_flags.contains(FileDescriptorFlags::FD_CLOEXEC) {
                            let old = dt
                                .set_fd_metadata(&typed_listener, FileDescriptorFlags::FD_CLOEXEC);
                            assert!(old.is_none());
                        }
                        typed_listener
                    };
                    {
                        let files = self.files.borrow();
                        let mut rds = files.raw_descriptor_store.write();
                        let _old_fd = rds
                            .fd_consume_raw_integer::<
                                super::broker_tcp_conn::BrokerTcpConnSubsystem,
                            >(raw_fd)
                            .map_err(|_| Errno::EBADF)?;
                        assert!(rds.fd_into_specific_raw_integer(typed_listener, raw_fd));
                    }
                    let _ = self.global.litebox.descriptor_table_mut().remove(typed);
                    Ok(())
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetListener => self
                .try_with_broker_inet_listener(sockfd, |typed| {
                    let raw = socket_address_to_inet_listener_wire(sockaddr.clone())?;
                    let handle = self.broker_inet_listener_handle(typed)?;
                    handle.with_entry(|entry| entry.bind(&raw)).map(|_| ())
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetDgram => self
                .try_with_broker_inet_dgram(sockfd, |typed| {
                    let raw = socket_address_to_inet_listener_wire(sockaddr.clone())?;
                    let handle = self.broker_inet_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.bind(&raw)).map(|_| ())
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketDgram => self
                .try_with_broker_socket_dgram(sockfd, |typed| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    let handle = self.broker_socket_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.bind(addr)).map(|_| ())
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |typed| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    let handle = self.broker_unix_stream_handle(typed)?;
                    handle.with_entry(|entry| entry.bind(addr)).map(|_| ())
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketSeqPacket => self
                .try_with_broker_socket_seqpacket(sockfd, |typed| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    let handle = self.broker_socket_seqpacket_handle(typed)?;
                    handle.with_entry(|entry| entry.bind(addr)).map(|_| ())
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketPair
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => self.files.borrow().with_socket(
                &self.global,
                sockfd,
                |fd| {
                    #[cfg(feature = "worker_local_inet")]
                    {
                        let addr = sockaddr.clone().inet().ok_or(Errno::EAFNOSUPPORT)?;
                        self.global.bind(fd, addr)
                    }
                    #[cfg(not(feature = "worker_local_inet"))]
                    {
                        let _ = fd;
                        Err(Errno::ENOTSOCK)
                    }
                },
                |file| {
                    let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                    file.bind(self, addr)
                },
            ),
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `listen`
    pub(crate) fn sys_listen(&self, sockfd: i32, backlog: u16) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        self.do_listen(sockfd, backlog)
    }
    pub(super) fn do_listen(&self, sockfd: u32, backlog: u16) -> Result<(), Errno> {
        let class = self.socket_io_class_of(sockfd)?;
        match class {
            SocketIoClass::BrokerInetListener => self
                .try_with_broker_inet_listener(sockfd, |typed| {
                    let handle = self.broker_inet_listener_handle(typed)?;
                    handle.with_entry(|entry| entry.listen(u32::from(backlog)))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |typed| {
                    let handle = self.broker_unix_stream_handle(typed)?;
                    handle.with_entry(|entry| entry.listen(u32::from(backlog)))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketSeqPacket => self
                .try_with_broker_socket_seqpacket(sockfd, |typed| {
                    let handle = self.broker_socket_seqpacket_handle(typed)?;
                    handle.with_entry(|entry| entry.listen(u32::from(backlog)))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketPair
            | SocketIoClass::BrokerSocketDgram
            | SocketIoClass::BrokerTcpConn
            | SocketIoClass::BrokerInetDgram
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => self.files.borrow().with_socket(
                &self.global,
                sockfd,
                |fd| {
                    #[cfg(feature = "worker_local_inet")]
                    {
                        self.global.listen(fd, backlog)
                    }
                    #[cfg(not(feature = "worker_local_inet"))]
                    {
                        let _ = fd;
                        Err(Errno::ENOTSOCK)
                    }
                },
                |file| file.listen(self, backlog, &self.global),
            ),
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        }
    }

    #[cfg(feature = "worker_local_inet")]
    pub(crate) fn tcp_listen_worker_exec_bridge_spec(&self, raw_fd: usize) -> Option<String> {
        let fd = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<litebox::net::Network<crate::Platform>>(raw_fd)
                .ok()?
        };
        let dt = self.global.litebox.descriptor_table();
        let sock_type = dt.with_metadata(&fd, |ty: &SockType| *ty).ok()?;
        if sock_type != SockType::Stream {
            return None;
        }
        let reuse_port = self
            .global
            .with_socket_options(&fd, |options| options.reuse_port);
        if !reuse_port {
            return None;
        }
        let port = self.global.net.lock().get_local_addr(&fd).ok()?.port();
        if port == 0 {
            return None;
        }
        Some(alloc::format!("{raw_fd}:tcp_listen:{port}:1"))
    }

    #[cfg(not(feature = "worker_local_inet"))]
    pub(crate) fn tcp_listen_worker_exec_bridge_spec(&self, raw_fd: usize) -> Option<String> {
        let _ = (self, raw_fd);
        None
    }

    #[cfg(feature = "worker_local_inet")]
    pub(crate) fn install_tcp_listen_bridge_fd(
        &self,
        guest_fd: usize,
        port: u16,
        reuse_port: bool,
    ) -> Result<(), Errno> {
        let created_fd = self.do_socket(
            AddressFamily::INET,
            SockType::Stream,
            SockFlags::empty(),
            IPProtocol::TCP as u8,
        )? as usize;
        if created_fd != guest_fd {
            let typed = {
                let files = self.files.borrow();
                files
                    .raw_descriptor_store
                    .read()
                    .fd_from_raw_integer::<litebox::net::Network<crate::Platform>>(created_fd)
                    .map_err(|_| Errno::EBADF)?
            };
            let dup = self
                .global
                .litebox
                .descriptor_table_mut()
                .duplicate(&typed)
                .ok_or(Errno::EBADF)?;
            if self
                .files
                .borrow()
                .raw_descriptor_store
                .read()
                .is_alive(guest_fd)
            {
                self.do_close(guest_fd)?;
            }
            {
                let files = self.files.borrow();
                let mut rds = files.raw_descriptor_store.write();
                if !rds.fd_into_specific_raw_integer(dup, guest_fd) {
                    return Err(Errno::EBADF);
                }
            }
            self.do_close(created_fd)?;
        }
        let fd = {
            let files = self.files.borrow();
            files
                .raw_descriptor_store
                .read()
                .fd_from_raw_integer::<litebox::net::Network<crate::Platform>>(guest_fd)
                .map_err(|_| Errno::EBADF)?
        };
        self.global
            .with_socket_options_mut(&fd, |options| options.reuse_port = reuse_port);
        self.global.bind(
            &fd,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        )?;
        self.global.listen(&fd, 16)?;
        self.global.send_listen_route_transfer(port)
    }

    #[cfg(not(feature = "worker_local_inet"))]
    pub(crate) fn install_tcp_listen_bridge_fd(
        &self,
        guest_fd: usize,
        port: u16,
        reuse_port: bool,
    ) -> Result<(), Errno> {
        let _ = (self, guest_fd, port, reuse_port);
        Err(Errno::EOPNOTSUPP)
    }

    /// Get the local port for an INET socket. Returns None if not bound.
    pub(super) fn do_getsockname_inet_port(&self, sockfd: u32) -> Option<u16> {
        self.do_getsockname(sockfd)
            .ok()
            .and_then(SocketAddress::inet)
            .map(|addr| addr.port())
    }

    /// Handle syscall `shutdown`
    pub(crate) fn sys_shutdown(&self, sockfd: i32, how: i32) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        // SHUT_RD=0, SHUT_WR=1, SHUT_RDWR=2
        let (read, write) = match how {
            0 => (true, false),
            1 => (false, true),
            2 => (true, true),
            _ => return Err(Errno::EINVAL),
        };
        self.do_shutdown(sockfd, read, write)
    }
    #[deny(clippy::wildcard_enum_match_arm)]
    fn do_shutdown(&self, sockfd: u32, read: bool, write: bool) -> Result<(), Errno> {
        if let Some(result) = self.try_with_broker_unix_stream(sockfd, |typed| {
            let handle = self.broker_unix_stream_handle(typed)?;
            let how = match (read, write) {
                (true, false) => 0,
                (false, true) => 1,
                (true, true) => 2,
                (false, false) => return Ok(()),
            };
            handle.with_entry(|entry| entry.shutdown(how))
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_socket_seqpacket(sockfd, |typed| {
            let handle = self.broker_socket_seqpacket_handle(typed)?;
            let how = match (read, write) {
                (true, false) => 0,
                (false, true) => 1,
                (true, true) => 2,
                (false, false) => return Ok(()),
            };
            handle.with_entry(|entry| entry.shutdown(how))
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_socket_dgram(sockfd, |typed| {
            let handle = self.broker_socket_dgram_handle(typed)?;
            let how = match (read, write) {
                (true, false) => 0,
                (false, true) => 1,
                (true, true) => 2,
                (false, false) => return Ok(()),
            };
            handle.with_entry(|entry| entry.shutdown(how))
        }) {
            return result;
        }
        let files = self.files.borrow();
        files.run_on_raw_fd(sockfd as usize, |raw_fd_ref| match raw_fd_ref {
            crate::RawFdRef::Fs(_) => Err(Errno::ENOTSOCK),
            #[cfg(feature = "worker_local_inet")]
            crate::RawFdRef::Net(fd) => self.global.shutdown(fd, read, write),
            crate::RawFdRef::Eventfd(_) => Err(Errno::ENOTSOCK),
            crate::RawFdRef::Epoll(_) => Err(Errno::ENOTSOCK),
            crate::RawFdRef::Unix(fd) => {
                let handle = self
                    .global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .ok_or(Errno::EBADF)?;
                handle.with_entry(|entry| {
                    entry.shutdown(read, write);
                    Ok(())
                })
            }
            crate::RawFdRef::HostPassthroughFd(_) => Err(Errno::ENOTSOCK),
            crate::RawFdRef::BrokerPipe(_) => Err(Errno::ENOTSOCK),
            crate::RawFdRef::BrokerSocketPair(fd) => {
                let handle = self.broker_sp_handle(fd)?;
                handle.with_entry(|entry| entry.shutdown(read, write))
            }
            crate::RawFdRef::BrokerTcpConn(fd) => {
                let handle = self
                    .global
                    .litebox
                    .descriptor_table()
                    .entry_handle(fd)
                    .ok_or(Errno::EBADF)?;
                handle.with_entry(|entry| entry.shutdown(read, write))
            }
            crate::RawFdRef::BrokerInetListener(_) => Err(Errno::EINVAL),
            crate::RawFdRef::BrokerInetDgram(fd) => {
                let handle = self.broker_inet_dgram_handle(fd)?;
                let how = match (read, write) {
                    (true, false) => 0,
                    (false, true) => 1,
                    (true, true) => 2,
                    (false, false) => return Ok(()),
                };
                handle.with_entry(|entry| entry.shutdown(how))
            }
            crate::RawFdRef::BrokerSocketDgram(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerSocketSeqPacket(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerUnixStream(_) => Err(Errno::EBADF),
            crate::RawFdRef::BrokerInetRaw(_) => Err(Errno::EINVAL),
            crate::RawFdRef::BrokerPty(_) => Err(Errno::ENOTSOCK),
            crate::RawFdRef::Signalfd(_) | crate::RawFdRef::Inotify(_) => Err(Errno::ENOTSOCK),
        })?
    }

    /// Handle syscall `sendto`
    pub(crate) fn sys_sendto(
        &self,
        fd: i32,
        buf: ConstPtr<u8>,
        len: usize,
        flags: SendFlags,
        addr: Option<ConstPtr<u8>>,
        addrlen: u32,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        // Netlink socket: skip sockaddr parsing, handle directly.
        if self.netlink_sockets.borrow().contains_key(&fd) {
            let buf = buf.to_owned_slice(len).ok_or(Errno::EFAULT)?;
            return self
                .netlink_sockets
                .borrow_mut()
                .get_mut(&fd)
                .unwrap()
                .sendto(&buf)
                .map_err(|_| Errno::EINVAL);
        }
        let sockaddr = addr
            .map(|addr| read_sockaddr_from_user(addr, addrlen as usize))
            .transpose()?;
        let buf = buf.to_owned_slice(len).ok_or(Errno::EFAULT)?;
        self.do_sendto(fd, &buf, flags, sockaddr)
    }
    fn do_sendto(
        &self,
        sockfd: u32,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddress>,
    ) -> Result<usize, Errno> {
        // Netlink socket: parse request and generate response.
        if let Some(nl) = self.netlink_sockets.borrow_mut().get_mut(&sockfd) {
            return nl.sendto(buf).map_err(|_| Errno::EINVAL);
        }
        let class = self.socket_io_class_of(sockfd)?;
        let ret = match class {
            SocketIoClass::BrokerSocketPair => self
                .try_with_broker_sp(sockfd, |typed| {
                    if sockaddr.is_some() {
                        Err(Errno::EISCONN)
                    } else {
                        let handle = self.broker_sp_handle(typed)?;
                        handle.with_entry(|entry| entry.write(&self.wait_cx(), buf))
                    }
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerTcpConn => self
                .try_with_broker_tcp_conn(sockfd, |typed| {
                    if sockaddr.is_some() {
                        Err(Errno::EISCONN)
                    } else {
                        let handle = self
                            .global
                            .litebox
                            .descriptor_table()
                            .entry_handle(typed)
                            .ok_or(Errno::EBADF)?;
                        handle.with_entry(|entry| entry.write(&self.wait_cx(), buf))
                    }
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetDgram => self
                .try_with_broker_inet_dgram(sockfd, |typed| {
                    let raw = match sockaddr.clone() {
                        Some(addr) => socket_address_to_inet_listener_wire(addr)?.to_vec(),
                        None => Vec::new(),
                    };
                    let handle = self.broker_inet_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.sendto(&self.wait_cx(), &raw, buf))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketDgram => self
                .try_with_broker_socket_dgram(sockfd, |typed| {
                    let addr = sockaddr
                        .clone()
                        .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                        .transpose()?;
                    let handle = self.broker_socket_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.sendto(&self.wait_cx(), addr, buf, &[]))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |typed| {
                    if sockaddr.is_some() {
                        return Err(Errno::EISCONN);
                    }
                    let handle = self.broker_unix_stream_handle(typed)?;
                    handle.with_entry(|entry| entry.send(&self.wait_cx(), buf))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketSeqPacket => self
                .try_with_broker_socket_seqpacket(sockfd, |typed| {
                    if sockaddr.is_some() {
                        return Err(Errno::EISCONN);
                    }
                    let handle = self.broker_socket_seqpacket_handle(typed)?;
                    handle.with_entry(|entry| entry.send(&self.wait_cx(), buf, &[]))
                })
                .unwrap_or(Err(Errno::EBADF)),
            // inet-listener / inet-raw have no sendto fast path; preserve the
            // historical fall-through to `with_socket` (which rejects them).
            // AF_UNIX / worker-local inet are dispatched by `with_socket`.
            SocketIoClass::BrokerInetListener
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => self.files.borrow().with_socket(
                &self.global,
                sockfd,
                |fd| {
                    #[cfg(feature = "worker_local_inet")]
                    {
                        let sockaddr = sockaddr
                            .clone()
                            .map(|addr| addr.inet().ok_or(Errno::EAFNOSUPPORT))
                            .transpose()?;
                        self.global
                            .sendto(&self.wait_cx(), fd, buf, flags, sockaddr)
                    }
                    #[cfg(not(feature = "worker_local_inet"))]
                    {
                        let _ = fd;
                        Err(Errno::ENOTSOCK)
                    }
                },
                |file| {
                    let addr = sockaddr
                        .clone()
                        .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                        .transpose()?;
                    file.sendto(self, buf, flags, addr, Vec::new(), Vec::new())
                },
            ),
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        };
        // SIGPIPE on EPIPE for the stream-like sends that previously applied it
        // (socketpair, tcp_conn, and the `with_socket` path); never for the
        // datagram/seqpacket broker fast paths, matching prior behavior.
        let sigpipe_eligible = matches!(
            class,
            SocketIoClass::BrokerSocketPair
                | SocketIoClass::BrokerTcpConn
                | SocketIoClass::BrokerInetListener
                | SocketIoClass::BrokerInetRaw
                | SocketIoClass::WithSocket
        );
        if sigpipe_eligible
            && let Err(Errno::EPIPE) = ret
            && !flags.contains(SendFlags::NOSIGNAL)
        {
            self.send_signal(
                litebox_common_linux::signal::Signal::SIGPIPE,
                super::signal::siginfo_kernel(litebox_common_linux::signal::Signal::SIGPIPE),
            );
        }
        ret
    }

    /// Handle syscall `sendmsg`
    pub(crate) fn sys_sendmsg(
        &self,
        fd: i32,
        msg: ConstPtr<litebox_common_linux::UserMsgHdr<Platform>>,
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        // Netlink socket: extract data from iovs before sockaddr parsing.
        if self.netlink_sockets.borrow().contains_key(&fd) {
            let hdr = msg.read_at_offset(0).ok_or(Errno::EFAULT)?;
            if hdr.msg_iovlen > 1024 {
                return Err(Errno::EINVAL);
            }
            let iovs = hdr
                .msg_iov
                .to_owned_slice(hdr.msg_iovlen)
                .ok_or(Errno::EFAULT)?;
            let buf = Self::copy_sendmsg_iovs(&iovs)?;
            return self
                .netlink_sockets
                .borrow_mut()
                .get_mut(&fd)
                .unwrap()
                .sendto(&buf)
                .map_err(|_| Errno::EINVAL);
        }
        let msg = msg.read_at_offset(0).ok_or(Errno::EFAULT)?;
        self.do_sendmsg(fd, &msg, flags)
    }

    fn copy_sendmsg_iovs(
        iovs: &[litebox_common_linux::IoVec<MutPtr<u8>>],
    ) -> Result<Vec<u8>, Errno> {
        let total_len = iovs
            .iter()
            .try_fold(0usize, |acc, iov| acc.checked_add(iov.iov_len))
            .ok_or(Errno::EINVAL)?;
        let mut buf = Vec::with_capacity(total_len);
        for iov in iovs {
            let iov_base = iov.iov_base;
            let iov_len = iov.iov_len;
            let start = buf.len();
            buf.resize(start + iov_len, 0);
            let ptr = ConstPtr::<u8>::from_usize(iov_base.as_usize());
            for (offset, byte) in buf[start..].iter_mut().enumerate() {
                *byte = ptr
                    .read_at_offset(isize::try_from(offset).unwrap())
                    .ok_or(Errno::EFAULT)?;
            }
        }
        Ok(buf)
    }

    fn sendmsg_stream_iovs(
        iovs: &[litebox_common_linux::IoVec<MutPtr<u8>>],
        mut send_chunk: impl FnMut(&[u8]) -> Result<usize, Errno>,
    ) -> Result<usize, Errno> {
        let mut total_sent = 0usize;
        for iov in iovs {
            let iov_base = iov.iov_base;
            let iov_len = iov.iov_len;
            let mut offset = 0usize;
            while offset < iov_len {
                let ptr = ConstPtr::<u8>::from_usize(iov_base.as_usize().wrapping_add(offset));
                let chunk = ptr.to_owned_slice(iov_len - offset).ok_or(Errno::EFAULT)?;
                let sent = match send_chunk(&chunk) {
                    Ok(sent) => sent,
                    Err(_err) if total_sent > 0 => return Ok(total_sent),
                    Err(err) => return Err(err),
                };
                total_sent = total_sent.checked_add(sent).ok_or(Errno::EINVAL)?;
                if sent == 0 || sent < chunk.len() {
                    return Ok(total_sent);
                }
                offset += sent;
            }
        }
        Ok(total_sent)
    }

    /// Parse `SCM_RIGHTS` control messages from a `sendmsg` header.
    ///
    /// Iterates over the control-message buffer, validates each `cmsghdr`,
    /// and duplicates the referenced file descriptors for inter-process
    /// passing. Only `SOL_SOCKET` / `SCM_RIGHTS` is supported; any other
    /// cmsg level/type is rejected with `EOPNOTSUPP`.
    ///
    /// Returns `(passed_fds, passed_tokens)`. `passed_tokens` is
    /// populated for broker-backed subsystem entries (eventfd, pipes,
    /// and other cross-worker-transferable handles). The caller
    /// hands both to `sendto`, which routes them through the in-worker
    /// `Channel` arm (uses `passed_fds`) or the cross-worker `Tcp` arm
    /// (uses `passed_tokens` to LBFD-frame the broker handle ids).
    fn parse_sendmsg_cmsg(
        &self,
        msg: &litebox_common_linux::UserMsgHdr<Platform>,
    ) -> Result<
        (
            Vec<super::unix::PassedFd>,
            Vec<litebox_common_linux::fd_transfer_frame::PassedToken>,
        ),
        Errno,
    > {
        use litebox::platform::RawConstPointer as _;
        use litebox_common_linux::{CmsgHdr, SCM_RIGHTS, cmsg_align, cmsg_len};

        let controllen = msg.msg_controllen;
        if controllen == 0 {
            return Ok((Vec::new(), Vec::new()));
        }

        let msg_control = { msg.msg_control };
        let control_ptr = msg_control.as_usize();
        if control_ptr == 0 {
            return Err(Errno::EFAULT);
        }

        let hdr_size = core::mem::size_of::<CmsgHdr>();
        let mut passed_fds = Vec::new();
        let mut passed_tokens: Vec<litebox_common_linux::fd_transfer_frame::PassedToken> =
            Vec::new();
        let mut offset = 0usize;

        while offset + hdr_size <= controllen {
            let cmsg_ptr = ConstPtr::<CmsgHdr>::from_usize(control_ptr + offset);
            let cmsg: CmsgHdr = cmsg_ptr.read_at_offset(0).ok_or(Errno::EFAULT)?;

            if cmsg.cmsg_len < cmsg_len(0) {
                return Err(Errno::EINVAL);
            }

            // Validate that the full cmsg fits within the control buffer.
            if cmsg.cmsg_len > controllen - offset {
                return Err(Errno::EINVAL);
            }

            // SOL_SOCKET = 1 (SocketOptionLevel::SOCKET)
            if cmsg.cmsg_level != 1 || cmsg.cmsg_type != SCM_RIGHTS {
                return Err(Errno::EOPNOTSUPP);
            }

            let data_offset = cmsg_align(hdr_size);
            let data_len = cmsg.cmsg_len - data_offset;
            if !data_len.is_multiple_of(core::mem::size_of::<i32>()) {
                return Err(Errno::EINVAL);
            }
            let fd_count = data_len / core::mem::size_of::<i32>();
            if fd_count == 0 {
                // Advance past this cmsg.
                offset += cmsg_align(cmsg.cmsg_len);
                continue;
            }

            let fds_ptr = ConstPtr::<i32>::from_usize(control_ptr + offset + data_offset);
            let fd_array = fds_ptr.to_owned_slice(fd_count).ok_or(Errno::EFAULT)?;

            // Duplicate each fd for passing. Broker-file tokens are resolved
            // before taking descriptor_table_mut: layered FS fid lookup itself
            // reads the descriptor table, so doing it under the mutable fd-table
            // lock self-deadlocks.
            for &guest_fd in &fd_array {
                let raw_fd = usize::try_from(guest_fd).map_err(|_| Errno::EBADF)?;
                {
                    let files = self.files.borrow();
                    let sent_file_token =
                        files.run_on_raw_fd(raw_fd, |raw_fd_ref| -> Result<bool, Errno> {
                            let crate::RawFdRef::Fs(fd) = raw_fd_ref else {
                                return Ok(false);
                            };
                            let Some(provider) = super::broker_fs_provider() else {
                                return Ok(false);
                            };
                            let descriptors = self.global.litebox.descriptor_table();
                            let Some(fid) = files.fs.descriptor_backend_fid(fd, &*descriptors)
                            else {
                                return Ok(false);
                            };
                            let open_file_id = provider.register_ofd(fid).map_err(|err| {
                                super::broker_backed::broker_err_to_errno(err)
                            })?;
                            passed_tokens.push(
                                litebox_common_linux::cwfd::fd_transfer_frame::PassedToken::new(
                                    litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag::File,
                                    open_file_id,
                                )
                                .map_err(|_| Errno::EINVAL)?,
                            );
                            Ok(true)
                        })??;
                    if sent_file_token {
                        continue;
                    }
                }

                let mut dt = self.global.litebox.descriptor_table_mut();
                let files = self.files.borrow();
                let rds = files.raw_descriptor_store.read();

                let passed = rds
                    .duplicate_for_passing(raw_fd, &mut dt)
                    .ok_or(Errno::EBADF)?;
                drop(rds);
                drop(files);

                {
                    let files = self.files.borrow();
                    let broker_dgram = files
                        .raw_descriptor_store
                        .read()
                        .fd_from_raw_integer::<super::broker_socket_dgram::BrokerSocketDgramSubsystem>(raw_fd)
                        .ok();
                    if let Some(typed) = broker_dgram {
                        let Some(provider) =
                            super::broker_socket_dgram::broker_socket_dgram_provider()
                        else {
                            return Err(Errno::EOPNOTSUPP);
                        };
                        let entry_handle = dt
                            .entry_handle::<super::broker_socket_dgram::BrokerSocketDgramSubsystem>(
                                &typed,
                            )
                            .ok_or(Errno::EBADF)?;
                        let handle_id = entry_handle.with_entry(|e| e.handle());
                        provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                        passed_tokens.push(
                            litebox_common_linux::cwfd::fd_transfer_frame::PassedToken::new(
                                litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag::UnixSocket,
                                handle_id,
                            )
                            .map_err(|_| Errno::EINVAL)?,
                        );
                        continue;
                    }
                }

                let files = self.files.borrow();
                let sent_broker_token = files.run_on_raw_fd(raw_fd, |raw_fd_ref| -> Result<bool, Errno> {
                    match raw_fd_ref {
                        crate::RawFdRef::Fs(_) => Ok(false),
                        #[cfg(feature = "worker_local_inet")]
                        crate::RawFdRef::Net(_) => {
                            // Network descriptors are kernel-backed and transfer as PassedFd.
                            Ok(false)
                        }
                        crate::RawFdRef::Eventfd(typed) => {
                            let entry_handle = dt
                                .entry_handle::<super::eventfd::EventfdSubsystem>(typed)
                                .ok_or(Errno::EBADF)?;
                            let mut broker_info = entry_handle
                                .with_entry(|e| e.broker_backed_handle().zip(e.broker_backed_provider()));
                            if broker_info.is_none()
                                && let Some(provider) = super::eventfd::broker_eventfd_provider()
                            {
                                let promoted = entry_handle.with_entry(|e| {
                                    e.ensure_broker_backed_for_fork(Some(&provider), None)
                                });
                                if let Ok(Some(super::fork_snapshot::FdKind::Eventfd {
                                    handle_id,
                                })) = promoted
                                {
                                    broker_info = Some((handle_id, provider));
                                }
                            }
                            if let Some((handle_id, provider)) = broker_info {
                                // Found or promoted a broker-backed eventfd. Ask the broker
                                // to dup a transit ref so the handle survives
                                // until the receiver materialises its own ref.
                                provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                                passed_tokens.push(
                                    litebox_common_linux::fd_transfer_frame::PassedToken::new(
                                        litebox_common_linux::fd_transfer_frame::SubsystemTag::Eventfd,
                                        handle_id,
                                    )
                                    .map_err(|_| Errno::EINVAL)?,
                                );
                                Ok(true)
                            } else {
                                // Kernel-backed eventfds transfer as PassedFd.
                                Ok(false)
                            }
                        }
                        crate::RawFdRef::Epoll(_) => {
                            // Epoll descriptors are not broker-token-transferable yet.
                            Ok(false)
                        }
                        crate::RawFdRef::Unix(_) => {
                            // Unix sockets are kernel-backed and transfer as PassedFd.
                            Ok(false)
                        }
                        crate::RawFdRef::HostPassthroughFd(_) => {
                            // Host-passthrough fds are sealed host fds and transfer as PassedFd.
                            Ok(false)
                        }
                        crate::RawFdRef::BrokerPipe(typed) => {
                            let Some(provider) = super::broker_pipe::broker_pipe_provider() else {
                                return Ok(false);
                            };
                            let entry_handle = dt
                                .entry_handle::<super::broker_pipe::BrokerPipeSubsystem>(typed)
                                .ok_or(Errno::EBADF)?;
                            let (handle_id, direction) = entry_handle.with_entry(|e| {
                                (
                                    e.handle(),
                                    e.direction(),
                                )
                            });
                            provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                            let tag = match direction {
                                litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read => {
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::PipeRead
                                }
                                litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write => {
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::PipeWrite
                                }
                            };
                            passed_tokens.push(
                                litebox_common_linux::fd_transfer_frame::PassedToken::new(
                                    tag,
                                    handle_id,
                                )
                                .map_err(|_| Errno::EINVAL)?,
                            );
                            Ok(true)
                        }
                        crate::RawFdRef::BrokerSocketPair(typed) => {
                            let Some(provider) =
                                super::broker_socketpair::broker_socketpair_provider()
                            else {
                                return Ok(false);
                            };
                            let entry_handle = dt
                                .entry_handle::<super::broker_socketpair::BrokerSocketPairSubsystem>(
                                    typed,
                                )
                                .ok_or(Errno::EBADF)?;
                            let (handle_id, endpoint) =
                                entry_handle.with_entry(|e| (e.handle(), e.endpoint()));
                            provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                            let tag = match endpoint {
                                litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A => {
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::SocketPairA
                                }
                                litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::B => {
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::SocketPairB
                                }
                            };
                            passed_tokens.push(
                                litebox_common_linux::fd_transfer_frame::PassedToken::new(
                                    tag, handle_id,
                                )
                                .map_err(|_| Errno::EINVAL)?,
                            );
                            Ok(true)
                        }
                        crate::RawFdRef::BrokerTcpConn(typed) => {
                            let entry_handle = dt
                                .entry_handle::<super::broker_tcp_conn::BrokerTcpConnSubsystem>(typed)
                                .ok_or(Errno::EBADF)?;
                            let (handle_id, provider) = entry_handle.with_entry(|e| {
                                (
                                    e.handle(),
                                    super::broker_tcp_conn::broker_tcp_conn_provider(),
                                )
                            });
                            let Some(provider) = provider else {
                                return Ok(false);
                            };
                            provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                            passed_tokens.push(
                                litebox_common_linux::fd_transfer_frame::PassedToken::new(
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::TcpSocket,
                                    handle_id,
                                )
                                .map_err(|_| Errno::EINVAL)?,
                            );
                            Ok(true)
                        }
                        crate::RawFdRef::BrokerPty(typed) => {
                            let Some(provider) = super::broker_pty::broker_pty_provider() else {
                                return Ok(false);
                            };
                            let entry_handle = dt
                                .entry_handle::<super::broker_pty::BrokerPtySubsystem>(typed)
                                .ok_or(Errno::EBADF)?;
                            let (handle_id, is_master) =
                                entry_handle.with_entry(|e| (e.handle(), e.is_master()));
                            if !is_master {
                                // The LBFD Pty tag currently carries only the broker handle id.
                                // Master role can be recovered via TIOCGPTN; slave role cannot
                                // be reconstructed without extending the wire payload.
                                return Ok(false);
                            }
                            provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                            passed_tokens.push(
                                litebox_common_linux::fd_transfer_frame::PassedToken::new(
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::Pty,
                                    handle_id,
                                )
                                .map_err(|_| Errno::EINVAL)?,
                            );
                            Ok(true)
                        }
                        crate::RawFdRef::BrokerInetRaw(_) => {
                            // Broker raw sockets are not broker-token-transferable over SCM yet.
                            Ok(false)
                        }
                        crate::RawFdRef::BrokerInetListener(typed) => {
                            let entry_handle = dt
                                .entry_handle::<super::broker_inet_listener::BrokerInetListenerSubsystem>(typed)
                                .ok_or(Errno::EBADF)?;
                            let (handle_id, provider) =
                                entry_handle.with_entry(|e| (e.handle(), e.provider()));
                            provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                            passed_tokens.push(
                                litebox_common_linux::fd_transfer_frame::PassedToken::new(
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::InetListener,
                                    handle_id,
                                )
                                .map_err(|_| Errno::EINVAL)?,
                            );
                            Ok(true)
                        }
                        crate::RawFdRef::BrokerInetDgram(_) => Ok(false),
                        crate::RawFdRef::BrokerSocketDgram(_)
                        | crate::RawFdRef::BrokerSocketSeqPacket(_) => {
                            // Broker socket dgram/seqpacket are not broker-token-
                            // transferable over SCM yet.
                            Ok(false)
                        }
                        crate::RawFdRef::BrokerUnixStream(typed) => {
                            let Some(provider) =
                                super::broker_unix_stream::broker_unix_stream_provider()
                            else {
                                return Ok(false);
                            };
                            let entry_handle = dt
                                .entry_handle::<super::broker_unix_stream::BrokerUnixStreamSubsystem>(
                                    typed,
                                )
                                .ok_or(Errno::EBADF)?;
                            let handle_id = entry_handle.with_entry(|e| e.handle());
                            provider.dup_handle(handle_id).map_err(|_| Errno::EIO)?;
                            passed_tokens.push(
                                litebox_common_linux::fd_transfer_frame::PassedToken::new(
                                    litebox_common_linux::fd_transfer_frame::SubsystemTag::UnixStream,
                                    handle_id,
                                )
                                .map_err(|_| Errno::EINVAL)?,
                            );
                            Ok(true)
                        }
                        crate::RawFdRef::Signalfd(_) | crate::RawFdRef::Inotify(_) => Ok(false),
                    }
                })??;
                drop(files);

                if !sent_broker_token {
                    // Compile-time-exhaustive diagnosis (see `scm_passed_fd_kind`):
                    // a broker-backed fd that reaches this raw-`PassedFd`
                    // fallthrough was NOT tokenized, so the receiver gets a dead
                    // handle (node `SentHandleNotReceivedWarning` /
                    // "Could not find pty N"). Name the offending type loudly in
                    // the diag log instead of dropping it silently.
                    let kind = {
                        let files = self.files.borrow();
                        files
                            .run_on_raw_fd(raw_fd, |r| scm_passed_fd_kind(&r))
                            .unwrap_or(ScmPassedFdKind::KernelOrHostBacked)
                    };
                    if let ScmPassedFdKind::UnsupportedBrokerFd(name) = kind {
                        use litebox::platform::DebugLogProvider as _;
                        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                            "SCM_RIGHTS SEND: untokenized broker fd type '{name}' (raw={raw_fd}) passed as raw host fd; receiver will see a dead handle\n"
                        ));
                    }
                    passed_fds.push(passed);
                }
            }

            offset += cmsg_align(cmsg.cmsg_len);
        }

        Ok((passed_fds, passed_tokens))
    }

    /// Write an `SCM_RIGHTS` control message into the user's `msg_control`
    /// buffer. Updates `msg_controllen` with the actual bytes written, and
    /// sets `MSG_CTRUNC` in `msg_flags` if the buffer was too small.
    ///
    /// Returns the number of fds that were actually written to the control
    /// buffer. The caller must close any excess fds (matching Linux semantics
    /// where truncated SCM_RIGHTS fds are closed by the kernel).
    fn write_recvmsg_cmsg(
        &self,
        hdr: &mut litebox_common_linux::UserMsgHdr<Platform>,
        fds: &[i32],
        msg_flags: &mut ReceiveFlags,
    ) -> usize {
        use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
        use litebox_common_linux::{CmsgHdr, SCM_RIGHTS, cmsg_align, cmsg_len, cmsg_space};

        if fds.is_empty() {
            hdr.msg_controllen = 0;
            return 0;
        }

        let fd_data_len = core::mem::size_of_val(fds);
        let needed = cmsg_space(fd_data_len);
        let control_buf_len = hdr.msg_controllen;
        let msg_control = { hdr.msg_control };
        let control_ptr = msg_control.as_usize();

        if control_ptr == 0 || control_buf_len == 0 {
            *msg_flags |= ReceiveFlags::CTRUNC;
            hdr.msg_controllen = 0;
            return 0;
        }

        let hdr_size = core::mem::size_of::<CmsgHdr>();
        let data_offset = cmsg_align(hdr_size);

        // Check if we have room for at least the header + one fd.
        if control_buf_len < data_offset + core::mem::size_of::<i32>() {
            *msg_flags |= ReceiveFlags::CTRUNC;
            hdr.msg_controllen = 0;
            return 0;
        }

        // Determine how many fds fit in the available buffer.
        let available_data = control_buf_len.saturating_sub(data_offset);
        let fds_that_fit = available_data / core::mem::size_of::<i32>();
        let fds_to_write = fds.len().min(fds_that_fit);

        if fds_to_write < fds.len() {
            *msg_flags |= ReceiveFlags::CTRUNC;
        }

        // Write the cmsghdr with the *actual* payload length.
        let written_data_len = fds_to_write * core::mem::size_of::<i32>();
        let cmsg_hdr = CmsgHdr {
            cmsg_len: cmsg_len(written_data_len),
            cmsg_level: 1, // SOL_SOCKET
            cmsg_type: SCM_RIGHTS,
        };
        let cmsg_ptr = MutPtr::<CmsgHdr>::from_usize(control_ptr);
        if cmsg_ptr.write_at_offset(0, cmsg_hdr).is_none() {
            *msg_flags |= ReceiveFlags::CTRUNC;
            hdr.msg_controllen = 0;
            return 0;
        }

        // Write the fd array.
        if fds_to_write > 0 {
            let fd_ptr = MutPtr::<u8>::from_usize(control_ptr + data_offset);
            let fd_bytes: &[u8] = zerocopy::IntoBytes::as_bytes(&fds[..fds_to_write]);
            let _ = fd_ptr.copy_from_slice(0, fd_bytes);
        }

        // Cap msg_controllen to the buffer actually available.
        let reported = if fds_to_write == fds.len() {
            needed
        } else {
            cmsg_space(written_data_len)
        };
        hdr.msg_controllen = reported.min(control_buf_len);
        fds_to_write
    }

    fn do_sendmsg(
        &self,
        sockfd: u32,
        msg: &litebox_common_linux::UserMsgHdr<Platform>,
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        // Netlink socket: extract data from iovs and handle via sendto.
        if self.netlink_sockets.borrow().contains_key(&sockfd) {
            if msg.msg_iovlen > 1024 {
                return Err(Errno::EINVAL);
            }
            let iovs = msg
                .msg_iov
                .to_owned_slice(msg.msg_iovlen)
                .ok_or(Errno::EFAULT)?;
            let buf = Self::copy_sendmsg_iovs(&iovs)?;
            return self
                .netlink_sockets
                .borrow_mut()
                .get_mut(&sockfd)
                .unwrap()
                .sendto(&buf)
                .map_err(|_| Errno::EINVAL);
        }

        let msg_name = msg.msg_name;
        let sock_addr = if msg_name.as_usize() != 0 {
            Some(read_sockaddr_from_user(
                msg.msg_name,
                msg.msg_namelen as usize,
            )?)
        } else {
            None
        };
        if msg.msg_iovlen > 1024 {
            return Err(Errno::EINVAL);
        }
        let iovs = msg
            .msg_iov
            .to_owned_slice(msg.msg_iovlen)
            .ok_or(Errno::EFAULT)?;
        let total_len = iovs
            .iter()
            .try_fold(0usize, |acc, iov| acc.checked_add(iov.iov_len))
            .ok_or(Errno::EINVAL)?;
        let class = self.socket_io_class_of(sockfd)?;
        let ret = match class {
            SocketIoClass::BrokerSocketPair => self
                .try_with_broker_sp(sockfd, |typed| {
                    if sock_addr.is_some() {
                        Err(Errno::EISCONN)
                    } else {
                        let handle = self.broker_sp_handle(typed)?;
                        if msg.msg_controllen != 0 {
                            let (passed_fds, passed_tokens) = self.parse_sendmsg_cmsg(msg)?;
                            if !passed_fds.is_empty() {
                                return Err(Errno::EOPNOTSUPP);
                            }
                            let data = Self::copy_sendmsg_iovs(&iovs)?;
                            let mut frame = Vec::new();
                            FdTransferFrame {
                                tokens: &passed_tokens,
                                data: &data,
                            }
                            .encode(&mut frame)
                            .map_err(|_| Errno::EMSGSIZE)?;
                            handle.with_entry(|entry| entry.write(&self.wait_cx(), &frame))?;
                            Ok(total_len)
                        } else if total_len == 0 {
                            handle.with_entry(|entry| entry.write(&self.wait_cx(), &[]))
                        } else {
                            Self::sendmsg_stream_iovs(&iovs, |chunk| {
                                handle.with_entry(|entry| entry.write(&self.wait_cx(), chunk))
                            })
                        }
                    }
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerTcpConn => self
                .try_with_broker_tcp_conn(sockfd, |typed| {
                    // Broker-held inet TCP connection. `do_sendto`/`write` already
                    // handle this; `sendmsg` must too, otherwise musl's resolver —
                    // which sends its DNS-over-TCP fallback query via `sendmsg`
                    // rather than `send`/`write` like glibc — gets ENOTSOCK and
                    // fails to resolve CNAME-heavy names (the truncated-UDP→TCP
                    // fallback path). See `BL.dns_resolve_cname_heavy.*musl*`.
                    if sock_addr.is_some() {
                        return Err(Errno::EISCONN);
                    }
                    if msg.msg_controllen != 0 {
                        let (passed_fds, _passed_tokens) = self.parse_sendmsg_cmsg(msg)?;
                        if !passed_fds.is_empty() {
                            // SCM_RIGHTS fd passing is not meaningful on a TCP stream.
                            return Err(Errno::EOPNOTSUPP);
                        }
                    }
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(typed)
                        .ok_or(Errno::EBADF)?;
                    if total_len == 0 {
                        handle.with_entry(|entry| entry.write(&self.wait_cx(), &[]))
                    } else {
                        Self::sendmsg_stream_iovs(&iovs, |chunk| {
                            handle.with_entry(|entry| entry.write(&self.wait_cx(), chunk))
                        })
                    }
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetDgram => self
                .try_with_broker_inet_dgram(sockfd, |typed| {
                    if msg.msg_controllen != 0 {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    let raw = match sock_addr.clone() {
                        Some(addr) => socket_address_to_inet_listener_wire(addr)?.to_vec(),
                        None => Vec::new(),
                    };
                    let buf = Self::copy_sendmsg_iovs(&iovs)?;
                    let handle = self.broker_inet_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.sendto(&self.wait_cx(), &raw, &buf))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketDgram => self
                .try_with_broker_socket_dgram(sockfd, |typed| {
                    let (passed_fds, passed_tokens) = self.parse_sendmsg_cmsg(msg)?;
                    if !passed_fds.is_empty() {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    let addr = sock_addr
                        .clone()
                        .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                        .transpose()?;
                    let buf = Self::copy_sendmsg_iovs(&iovs)?;
                    let handle = self.broker_socket_dgram_handle(typed)?;
                    handle.with_entry(|entry| {
                        entry.sendto(&self.wait_cx(), addr, &buf, &passed_tokens)
                    })
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |typed| {
                    if sock_addr.is_some() {
                        return Err(Errno::EISCONN);
                    }
                    let handle = self.broker_unix_stream_handle(typed)?;
                    if msg.msg_controllen != 0 {
                        // SCM_RIGHTS over the connected stream: broker-backed fds
                        // ride in-band as tokens inside an LBFD frame (same
                        // mechanism as the broker socketpair); raw host fds are
                        // not transferable on this path.
                        let (passed_fds, passed_tokens) = self.parse_sendmsg_cmsg(msg)?;
                        if !passed_fds.is_empty() {
                            return Err(Errno::EOPNOTSUPP);
                        }
                        let data = Self::copy_sendmsg_iovs(&iovs)?;
                        let mut frame = Vec::new();
                        FdTransferFrame {
                            tokens: &passed_tokens,
                            data: &data,
                        }
                        .encode(&mut frame)
                        .map_err(|_| Errno::EMSGSIZE)?;
                        handle.with_entry(|entry| entry.send(&self.wait_cx(), &frame))?;
                        Ok(total_len)
                    } else if total_len == 0 {
                        handle.with_entry(|entry| entry.send(&self.wait_cx(), &[]))
                    } else {
                        Self::sendmsg_stream_iovs(&iovs, |chunk| {
                            handle.with_entry(|entry| entry.send(&self.wait_cx(), chunk))
                        })
                    }
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketSeqPacket => self
                .try_with_broker_socket_seqpacket(sockfd, |typed| {
                    let (passed_fds, passed_tokens) = self.parse_sendmsg_cmsg(msg)?;
                    if !passed_fds.is_empty() {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    if sock_addr.is_some() {
                        return Err(Errno::EISCONN);
                    }
                    let buf = Self::copy_sendmsg_iovs(&iovs)?;
                    let handle = self.broker_socket_seqpacket_handle(typed)?;
                    handle.with_entry(|entry| entry.send(&self.wait_cx(), &buf, &passed_tokens))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetListener
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => self.files.borrow().with_socket(
                &self.global,
                sockfd,
                |fd| {
                    #[cfg(feature = "worker_local_inet")]
                    {
                        // Inet sockets do not support ancillary data.
                        if msg.msg_controllen != 0 {
                            return Err(Errno::EOPNOTSUPP);
                        }
                        let sock_addr = sock_addr
                            .clone()
                            .map(|addr| addr.inet().ok_or(Errno::EAFNOSUPPORT))
                            .transpose()?;
                        if self.global.get_socket_type(fd)? == SockType::Stream {
                            if total_len == 0 {
                                return self.global.sendto(
                                    &self.wait_cx(),
                                    fd,
                                    &[],
                                    flags,
                                    sock_addr,
                                );
                            }
                            Self::sendmsg_stream_iovs(&iovs, |chunk| {
                                self.global
                                    .sendto(&self.wait_cx(), fd, chunk, flags, sock_addr)
                            })
                        } else {
                            let buf = Self::copy_sendmsg_iovs(&iovs)?;
                            self.global
                                .sendto(&self.wait_cx(), fd, &buf, flags, sock_addr)
                        }
                    }
                    #[cfg(not(feature = "worker_local_inet"))]
                    {
                        let _ = fd;
                        Err(Errno::ENOTSOCK)
                    }
                },
                |file| {
                    // Parse SCM_RIGHTS ancillary data for unix sockets.
                    let (passed_fds, passed_tokens) = self.parse_sendmsg_cmsg(msg)?;
                    let sock_addr = sock_addr
                        .clone()
                        .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                        .transpose()?;
                    if file.sock_type() == SockType::Stream {
                        if total_len == 0 {
                            return file.sendto(
                                self,
                                &[],
                                flags,
                                sock_addr.clone(),
                                passed_fds,
                                passed_tokens,
                            );
                        }
                        // For stream sockets with ancillary data, attach fds to
                        // the first chunk only (matching Linux semantics).
                        let mut fds = Some(passed_fds);
                        let mut tokens = Some(passed_tokens);
                        Self::sendmsg_stream_iovs(&iovs, |chunk| {
                            file.sendto(
                                self,
                                chunk,
                                flags,
                                sock_addr.clone(),
                                fds.take().unwrap_or_default(),
                                tokens.take().unwrap_or_default(),
                            )
                        })
                    } else {
                        let buf = Self::copy_sendmsg_iovs(&iovs)?;
                        file.sendto(self, &buf, flags, sock_addr, passed_fds, passed_tokens)
                    }
                },
            ),
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        };
        let sigpipe_eligible = matches!(
            class,
            SocketIoClass::BrokerSocketPair
                | SocketIoClass::BrokerTcpConn
                | SocketIoClass::BrokerInetListener
                | SocketIoClass::BrokerInetRaw
                | SocketIoClass::WithSocket
        );
        if sigpipe_eligible
            && let Err(Errno::EPIPE) = ret
            && !flags.contains(SendFlags::NOSIGNAL)
        {
            self.send_signal(
                litebox_common_linux::signal::Signal::SIGPIPE,
                super::signal::siginfo_kernel(litebox_common_linux::signal::Signal::SIGPIPE),
            );
        }
        ret
    }

    /// Handle syscall `sendmmsg` — send multiple messages on a socket.
    pub(crate) fn sys_sendmmsg(
        &self,
        fd: i32,
        msgvec: MutPtr<litebox_common_linux::UserMmsgHdr<Platform>>,
        vlen: u32,
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let mut sent_count = 0u32;
        for i in 0..vlen {
            let mmsg_ptr = MutPtr::<litebox_common_linux::UserMmsgHdr<Platform>>::from_usize(
                msgvec.as_usize().wrapping_add(
                    i as usize
                        * core::mem::size_of::<litebox_common_linux::UserMmsgHdr<Platform>>(),
                ),
            );
            let mmsg = ConstPtr::<litebox_common_linux::UserMmsgHdr<Platform>>::from_usize(
                mmsg_ptr.as_usize(),
            )
            .read_at_offset(0)
            .ok_or(Errno::EFAULT)?;

            match self.do_sendmsg(sockfd, &mmsg.msg_hdr, flags) {
                Ok(bytes_sent) => {
                    // Write back the number of bytes sent for this message.
                    let msg_len_offset =
                        core::mem::size_of::<litebox_common_linux::UserMsgHdr<Platform>>();
                    let msg_len_ptr =
                        MutPtr::<u32>::from_usize(mmsg_ptr.as_usize().wrapping_add(msg_len_offset));
                    #[allow(clippy::cast_possible_truncation)]
                    let _ = msg_len_ptr.write_at_offset(0, bytes_sent as u32);
                    sent_count += 1;
                }
                Err(e) => {
                    if sent_count == 0 {
                        return Err(e);
                    }
                    break;
                }
            }
        }
        Ok(sent_count as usize)
    }

    /// Handle syscall `recvfrom`
    pub(crate) fn sys_recvfrom(
        &self,
        fd: i32,
        buf: MutPtr<u8>,
        len: usize,
        flags: ReceiveFlags,
        addr: Option<MutPtr<u8>>,
        addrlen: MutPtr<u32>,
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
        let copied_size = size.min(recv_buf.len());
        buf.copy_from_slice(0, &recv_buf[..copied_size])
            .ok_or(Errno::EFAULT)?;
        if let Some(src_addr) = source_addr
            && let Some(sock_ptr) = addr
        {
            write_sockaddr_to_user(src_addr, sock_ptr, addrlen)?;
        }
        if flags.contains(ReceiveFlags::TRUNC) {
            Ok(size)
        } else {
            Ok(copied_size)
        }
    }

    /// Handle syscall `recvmsg`
    pub(crate) fn sys_recvmsg(
        &self,
        fd: i32,
        msg: MutPtr<litebox_common_linux::UserMsgHdr<Platform>>,
        flags: ReceiveFlags,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        // Netlink socket: return buffered response data.
        if let Some(nl) = self.netlink_sockets.borrow_mut().get_mut(&sockfd) {
            if !nl.has_data() {
                return Ok(0);
            }

            let is_peek = flags.contains(ReceiveFlags::PEEK);
            let is_trunc = flags.contains(ReceiveFlags::TRUNC);

            // MSG_PEEK | MSG_TRUNC with zero-length iov: glibc's size-query pattern.
            // Return total buffered data length without consuming anything.
            if is_peek && is_trunc {
                let data_len = nl.recv_buf_len();
                // Still need to write msg_name/flags to the msghdr.
                let mut hdr = ConstPtr::<litebox_common_linux::UserMsgHdr<Platform>>::from_usize(
                    msg.as_usize(),
                )
                .read_at_offset(0)
                .ok_or(Errno::EFAULT)?;
                let msg_name_addr = {
                    let x = hdr.msg_name;
                    x.as_usize()
                };
                if msg_name_addr != 0 && hdr.msg_namelen >= 12 {
                    let kernel_addr: [u8; 12] = {
                        let mut a = [0u8; 12];
                        a[0..2].copy_from_slice(&16u16.to_ne_bytes()); // AF_NETLINK
                        a
                    };
                    let name_ptr = MutPtr::<u8>::from_usize(msg_name_addr);
                    for (i, &b) in kernel_addr.iter().enumerate() {
                        name_ptr.write_at_offset(i as isize, b);
                    }
                    hdr.msg_namelen = 12;
                } else {
                    hdr.msg_namelen = 0;
                }
                hdr.msg_controllen = 0;
                hdr.msg_flags = ReceiveFlags::empty();
                let _ = msg.write_at_offset(0, hdr);
                return Ok(data_len);
            }

            let mut hdr =
                ConstPtr::<litebox_common_linux::UserMsgHdr<Platform>>::from_usize(msg.as_usize())
                    .read_at_offset(0)
                    .ok_or(Errno::EFAULT)?;
            if hdr.msg_iovlen == 0 {
                return Err(Errno::EINVAL);
            }
            let iovs = hdr
                .msg_iov
                .to_owned_slice(hdr.msg_iovlen)
                .ok_or(Errno::EFAULT)?;

            let mut total_written = 0;
            // Capture total data size before draining for MSG_TRUNC.
            let original_data_len = nl.recv_buf_len();
            for iov in &iovs {
                if iov.iov_len == 0 {
                    continue;
                }
                let mut buf = alloc::vec![0u8; iov.iov_len];
                let n = if is_peek {
                    nl.peek(&mut buf)
                } else {
                    nl.recv(&mut buf)
                };
                if n == 0 {
                    break;
                }
                let iov_base = iov.iov_base;
                let dest = MutPtr::<u8>::from_usize(iov_base.as_usize());
                for (i, &byte) in buf[..n].iter().enumerate() {
                    dest.write_at_offset(i as isize, byte);
                }
                total_written += n;
                if n < iov.iov_len {
                    break;
                }
            }
            // Write kernel source address (nl_pid=0) to msg_name if provided.
            let msg_name_addr = {
                let x = hdr.msg_name;
                x.as_usize()
            };
            let msg_name_len = hdr.msg_namelen;
            if msg_name_addr != 0 && msg_name_len >= 12 {
                // sockaddr_nl: family(2) + pad(2) + pid(4) + groups(4) = 12
                let kernel_addr: [u8; 12] = {
                    let mut a = [0u8; 12];
                    a[0..2].copy_from_slice(&16u16.to_ne_bytes()); // AF_NETLINK
                    // nl_pid = 0 (kernel), nl_groups = 0
                    a
                };
                let name_ptr = MutPtr::<u8>::from_usize(msg_name_addr);
                for (i, &b) in kernel_addr.iter().enumerate() {
                    name_ptr.write_at_offset(i as isize, b);
                }
                hdr.msg_namelen = 12;
            } else {
                hdr.msg_namelen = 0;
            }
            hdr.msg_controllen = 0;
            hdr.msg_flags = ReceiveFlags::empty();
            let _ = msg.write_at_offset(0, hdr);
            // For MSG_TRUNC, return the full data size (may be > total_written).
            let result = if is_trunc {
                original_data_len
            } else {
                total_written
            };
            return Ok(result);
        }

        let mut hdr =
            ConstPtr::<litebox_common_linux::UserMsgHdr<Platform>>::from_usize(msg.as_usize())
                .read_at_offset(0)
                .ok_or(Errno::EFAULT)?;
        if hdr.msg_iovlen == 0 || hdr.msg_iovlen > 1024 {
            return Err(Errno::EINVAL);
        }

        let iovs = hdr
            .msg_iov
            .to_owned_slice(hdr.msg_iovlen)
            .ok_or(Errno::EFAULT)?;
        let total_len = iovs
            .iter()
            .try_fold(0usize, |acc, iov| acc.checked_add(iov.iov_len))
            .ok_or(Errno::EINVAL)?;
        let mut recv_buf = alloc::vec![0; total_len.min(0x80_000)];

        let msg_name = hdr.msg_name;
        let want_source = msg_name.as_usize() != 0;
        let mut source_addr = None;
        let mut received_fds = Vec::new();
        let mut received_tokens: Vec<litebox_common_linux::fd_transfer_frame::PassedToken> =
            Vec::new();
        let size = self.do_recvfrom_with_fds(
            sockfd,
            &mut recv_buf,
            flags,
            if want_source {
                Some(&mut source_addr)
            } else {
                None
            },
            &mut received_fds,
            &mut received_tokens,
        )?;

        let copied_len = size.min(recv_buf.len());
        let mut copied = 0usize;
        for iov in &iovs {
            if copied >= copied_len {
                break;
            }
            let len = iov.iov_len.min(copied_len - copied);
            iov.iov_base
                .copy_from_slice(0, &recv_buf[copied..copied + len])
                .ok_or(Errno::EFAULT)?;
            copied += len;
        }

        if let Some(src_addr) = source_addr {
            let name_ptr = MutPtr::<u8>::from_usize(msg_name.as_usize());
            let mut name_len = hdr.msg_namelen;
            write_sockaddr_to_user(
                src_addr,
                name_ptr,
                MutPtr::from_usize((&raw mut name_len).cast::<u32>() as usize),
            )?;
            hdr.msg_namelen = name_len;
        } else {
            hdr.msg_namelen = 0;
        }

        let mut msg_flags = ReceiveFlags::empty();
        if size > copied_len {
            msg_flags |= ReceiveFlags::TRUNC;
        }

        // Install received fds and format SCM_RIGHTS control message.
        // Phase B-Step8e/recv: tokens (cross-worker broker-backed
        // handles, e.g. eventfds passed via LBFD) are materialised
        // alongside received_fds. Materialised tokens contribute fresh
        // raw fds into `installed_fds` and are surfaced through the
        // same SCM_RIGHTS control message as ordinary received fds —
        // the user-space recipient cannot distinguish a broker-backed
        // eventfd from a local one.
        if received_fds.is_empty() && received_tokens.is_empty() {
            hdr.msg_controllen = 0;
        } else {
            let cloexec = flags.contains(ReceiveFlags::CMSG_CLOEXEC);
            let mut installed_fds = Vec::with_capacity(received_fds.len() + received_tokens.len());
            {
                let files = self.files.borrow();
                let mut rds = files.raw_descriptor_store.write();
                for passed_fd in received_fds {
                    let raw_fd = rds.insert_passed_fd(passed_fd);
                    installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                }
            }

            // Materialise broker tokens into descriptor table entries.
            for token in received_tokens {
                use litebox_common_linux::fd_transfer_frame::SubsystemTag;
                match token.tag() {
                    SubsystemTag::File => {
                        let Some(provider) = super::broker_fs_provider() else {
                            return Err(Errno::ENODEV);
                        };
                        let new_fid = self.fs_allocate_fid_number()?;
                        if let Err(err) = provider.clone_ofd(token.id(), new_fid) {
                            self.fs_free_fid_number(new_fid);
                            return Err(super::broker_backed::broker_err_to_errno(err));
                        }
                        let mut descriptors = self.global.litebox.descriptor_table_mut();
                        let file = match self.files.borrow().fs.wrap_existing_fid(
                            new_fid,
                            "",
                            litebox::fs::OFlags::empty(),
                            &mut *descriptors,
                        ) {
                            Ok(file) => file,
                            Err(_) => {
                                self.fs_clunk_fid_number(new_fid);
                                return Err(Errno::EINVAL);
                            }
                        };
                        if cloexec {
                            let _ = self.global.litebox.descriptor_table_mut().set_fd_metadata(
                                &file,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        let files = self.files.borrow();
                        match files.insert_raw_fd(file) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(file) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&file)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::UnixSocket => {
                        let Some(provider) =
                            super::broker_socket_dgram::broker_socket_dgram_provider()
                        else {
                            continue;
                        };
                        let handle_id = token.id();
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        let socket =
                            super::broker_socket_dgram::BrokerSocketDgramFd::<Platform>::new(
                                provider,
                                handle_id,
                                litebox::fs::OFlags::empty(),
                            );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt
                            .insert::<super::broker_socket_dgram::BrokerSocketDgramSubsystem>(
                                socket,
                            );
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX))
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::SocketPairA | SubsystemTag::SocketPairB => {
                        let Some(provider) = super::broker_socketpair::broker_socketpair_provider()
                        else {
                            continue;
                        };
                        let handle_id = token.id();
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        let endpoint = match token.tag() {
                            SubsystemTag::SocketPairA => {
                                litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::A
                            }
                            SubsystemTag::SocketPairB => {
                                litebox_common_linux::broker_socketpair_provider::BrokerSocketPairEndpoint::B
                            }
                            SubsystemTag::Eventfd
                            | SubsystemTag::TcpSocket
                            | SubsystemTag::Pidfd
                            | SubsystemTag::UnixSocket
                            | SubsystemTag::Signalfd
                            | SubsystemTag::Timerfd
                            | SubsystemTag::Inotify
                            | SubsystemTag::Process
                            | SubsystemTag::Pipe
                            | SubsystemTag::PipeRead
                            | SubsystemTag::PipeWrite
                            | SubsystemTag::Pty
                            | SubsystemTag::InetListener
                            | SubsystemTag::InetDgram
                            | SubsystemTag::InetRaw
                            | SubsystemTag::HostFd
                            | SubsystemTag::File
                            | SubsystemTag::UnixStream
                            | SubsystemTag::Unknown(_) => unreachable!(),
                        };
                        let socket = super::broker_socketpair::BrokerSocketPairFd::<Platform>::new(
                            provider,
                            handle_id,
                            endpoint,
                            litebox::fs::OFlags::empty(),
                        );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt
                            .insert::<super::broker_socketpair::BrokerSocketPairSubsystem>(socket);
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::UnixStream => {
                        let Some(provider) =
                            super::broker_unix_stream::broker_unix_stream_provider()
                        else {
                            continue;
                        };
                        let handle_id = token.id();
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        let stream = super::broker_unix_stream::BrokerUnixStreamFd::<Platform>::new(
                            provider,
                            handle_id,
                            litebox::fs::OFlags::empty(),
                        );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt
                            .insert::<super::broker_unix_stream::BrokerUnixStreamSubsystem>(stream);
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::Eventfd => {
                        let Some(provider) = super::eventfd::broker_eventfd_provider() else {
                            // No provider on this worker — drop the
                            // token; broker will eventually release
                            // when sender closes its own ref. Without
                            // a provider we cannot materialise.
                            continue;
                        };
                        let handle_id = token.id();
                        // The sender's SCM path dup'd a transit ref to keep
                        // the broker state alive while the LBFD frame was in
                        // flight. The receiver must also acquire the handle on
                        // its own broker connection before installing the fd;
                        // otherwise its later close/release is rejected as
                        // "not owned by this connection" and the control
                        // socket is torn down.
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        // Apply MSG_CMSG_CLOEXEC right at construction
                        // (matches Linux recvmsg semantics where the
                        // received fd is created with CLOEXEC atomically).
                        let efd_flags = if cloexec {
                            litebox_common_linux::EfdFlags::CLOEXEC
                        } else {
                            litebox_common_linux::EfdFlags::empty()
                        };
                        let eventfd = super::eventfd::EventFile::new_broker_backed(
                            provider, handle_id, efd_flags,
                        );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt.insert::<super::eventfd::EventfdSubsystem>(eventfd);
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::InetDgram => {
                        let Some(provider) = super::broker_inet_dgram::broker_inet_dgram_provider()
                        else {
                            continue;
                        };
                        let handle_id = token.id();
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        let dgram = super::broker_inet_dgram::BrokerInetDgramFd::<Platform>::new(
                            provider,
                            handle_id,
                            litebox::fs::OFlags::empty(),
                        );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed =
                            dt.insert::<super::broker_inet_dgram::BrokerInetDgramSubsystem>(dgram);
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX))
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::InetListener => {
                        let Some(provider) =
                            super::broker_inet_listener::broker_inet_listener_provider()
                        else {
                            continue;
                        };
                        let handle_id = token.id();
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        let status_flags = litebox::fs::OFlags::empty();
                        let listener =
                            super::broker_inet_listener::BrokerInetListenerFd::<Platform>::new(
                                provider,
                                handle_id,
                                0,
                                status_flags,
                            );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt
                            .insert::<super::broker_inet_listener::BrokerInetListenerSubsystem>(
                                listener,
                            );
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::TcpSocket => {
                        let Some(provider) = super::broker_tcp_conn::broker_tcp_conn_provider()
                        else {
                            continue;
                        };
                        let handle_id = token.id();
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        let status_flags = litebox::fs::OFlags::empty();
                        let conn = super::broker_tcp_conn::BrokerTcpConnFd::<Platform>::new(
                            provider,
                            handle_id,
                            status_flags,
                        );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed =
                            dt.insert::<super::broker_tcp_conn::BrokerTcpConnSubsystem>(conn);
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::PipeRead | SubsystemTag::PipeWrite => {
                        let Some(provider) = super::broker_pipe::broker_pipe_provider() else {
                            continue;
                        };
                        let handle_id = token.id();
                        if provider.dup_handle(handle_id).is_err() {
                            continue;
                        }
                        let direction = match token.tag() {
                            SubsystemTag::PipeRead => {
                                litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Read
                            }
                            SubsystemTag::PipeWrite => {
                                litebox_common_linux::broker_pipe_provider::BrokerPipeEnd::Write
                            }
                            SubsystemTag::Eventfd
                            | SubsystemTag::TcpSocket
                            | SubsystemTag::Pidfd
                            | SubsystemTag::UnixSocket
                            | SubsystemTag::Signalfd
                            | SubsystemTag::Timerfd
                            | SubsystemTag::Inotify
                            | SubsystemTag::Process
                            | SubsystemTag::Pipe
                            | SubsystemTag::Pty
                            | SubsystemTag::InetListener
                            | SubsystemTag::InetDgram
                            | SubsystemTag::InetRaw
                            | SubsystemTag::HostFd
                            | SubsystemTag::File
                            | SubsystemTag::SocketPairA
                            | SubsystemTag::SocketPairB
                            | SubsystemTag::UnixStream
                            | SubsystemTag::Unknown(_) => unreachable!(),
                        };
                        let pipe = super::broker_pipe::BrokerPipeFd::<Platform>::new(
                            provider,
                            handle_id,
                            direction,
                            litebox::fs::OFlags::empty(),
                            3,
                        );
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt.insert::<super::broker_pipe::BrokerPipeSubsystem>(pipe);
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::Pty => {
                        use super::broker_pty::BrokerPtyProviderReacquireExt as _;

                        let Some(provider) = super::broker_pty::broker_pty_provider() else {
                            continue;
                        };
                        let handle_id = token.id();
                        let pty = match provider.reacquire(
                            handle_id,
                            litebox_common_linux::broker_pty_provider::BrokerPtyRole::Master,
                            None,
                        ) {
                            Ok(pty) => pty,
                            Err(_) => continue,
                        };
                        pty.ensure_subscribed_eager();
                        let mut dt = self.global.litebox.descriptor_table_mut();
                        let typed = dt.insert::<super::broker_pty::BrokerPtySubsystem>(pty);
                        if cloexec {
                            let _ = dt.set_fd_metadata(
                                &typed,
                                litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC,
                            );
                        }
                        drop(dt);
                        let files = self.files.borrow();
                        match files.insert_raw_fd(typed) {
                            Ok(raw_fd) => {
                                installed_fds.push(i32::try_from(raw_fd).unwrap_or(i32::MAX));
                            }
                            Err(typed) => {
                                self.global
                                    .litebox
                                    .descriptor_table_mut()
                                    .remove(&typed)
                                    .unwrap();
                            }
                        }
                    }
                    SubsystemTag::Process | SubsystemTag::Unknown(_) => {
                        // Unsupported token kind on this worker; drop.
                    }
                    SubsystemTag::Pidfd
                    | SubsystemTag::Signalfd
                    | SubsystemTag::Timerfd
                    | SubsystemTag::Inotify
                    | SubsystemTag::Pipe
                    | SubsystemTag::InetRaw
                    | SubsystemTag::HostFd => {
                        // Reserved for P2.A/B/C and later phases.
                        // Until those subphases land, the receive
                        // path drops the fd cleanly rather than
                        // panicking. Each subphase replaces the
                        // matching arm here with proper
                        // materialisation logic.
                    }
                }
            }

            // Format the SCM_RIGHTS control message into the user buffer.
            let fds_written = self.write_recvmsg_cmsg(&mut hdr, &installed_fds, &mut msg_flags);

            // Close any excess fds that didn't fit in the control buffer
            // (matching Linux semantics where truncated SCM_RIGHTS fds are
            // closed by the kernel).
            for &excess_fd in &installed_fds[fds_written..] {
                let _ = self.sys_close(excess_fd);
            }
        }

        hdr.msg_flags = msg_flags;
        msg.write_at_offset(0, hdr).ok_or(Errno::EFAULT)?;
        if flags.contains(ReceiveFlags::TRUNC) {
            Ok(size)
        } else {
            Ok(copied_len)
        }
    }

    fn do_recvfrom(
        &self,
        sockfd: u32,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        // Netlink socket: return buffered response data.
        if let Some(nl) = self.netlink_sockets.borrow_mut().get_mut(&sockfd) {
            if !nl.has_data() {
                return Ok(0);
            }
            let is_peek = flags.contains(ReceiveFlags::PEEK);
            let is_trunc = flags.contains(ReceiveFlags::TRUNC);
            if is_peek && is_trunc {
                return Ok(nl.recv_buf_len());
            }
            let data_len = nl.recv_buf_len();
            let n = if is_peek { nl.peek(buf) } else { nl.recv(buf) };
            return Ok(if is_trunc { data_len } else { n });
        }
        self.do_recvfrom_with_fds(
            sockfd,
            buf,
            flags,
            source_addr,
            &mut Vec::new(),
            &mut Vec::new(),
        )
    }

    fn do_recvfrom_with_fds(
        &self,
        sockfd: u32,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
        received_fds: &mut Vec<super::unix::PassedFd>,
        received_tokens: &mut Vec<litebox_common_linux::fd_transfer_frame::PassedToken>,
    ) -> Result<usize, Errno> {
        let want_source = source_addr.is_some();
        // Exhaustive socket-I/O dispatch over the shared `socket_io_class` gate
        // (mirrors `do_sendto`); a new socket subsystem is an E0004 here instead
        // of silently falling through to `with_socket`/ENOTSOCK or — for the
        // broker stream types — tripping the `with_socket` panic net.
        match self.socket_io_class_of(sockfd)? {
            // F.8: broker-backed AF_UNIX SOCK_STREAM socketpair. recv() on a
            // connected stream socketpair degenerates to read(); SCM_RIGHTS
            // arrive in-band as LBFD frames interleaved with raw bytes.
            // `read_deframed` keeps a *persistent* reassembly reader on the
            // endpoint so coalesced / split frames are each surfaced with
            // their own fd tokens (a fresh-per-call reader silently dropped
            // every frame after the first coalesced one — the VS Code
            // exthost handle-passing stall). A connected socketpair has no
            // peer address, so `source_addr` is left unset (caller writes
            // msg_namelen 0).
            SocketIoClass::BrokerSocketPair => self
                .try_with_broker_sp(sockfd, |typed| {
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    let handle = self.broker_sp_handle(typed)?;
                    let (n, tokens) =
                        handle.with_entry(|entry| entry.read_deframed(&self.wait_cx(), buf))?;
                    received_tokens.extend(tokens);
                    Ok(n)
                })
                .unwrap_or(Err(Errno::EBADF)),
            // Connected broker TCP stream: recv() degenerates to read(); a
            // connected socket has no source address, so `source_addr` is left
            // unset for both the `want_source` and `!want_source` callers.
            SocketIoClass::BrokerTcpConn => self
                .try_with_broker_tcp_conn(sockfd, |typed| {
                    let handle = self
                        .global
                        .litebox
                        .descriptor_table()
                        .entry_handle(typed)
                        .ok_or(Errno::EBADF)?;
                    handle.with_entry(|entry| entry.read(&self.wait_cx(), buf))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetDgram => self
                .try_with_broker_inet_dgram(sockfd, |typed| {
                    let handle = self.broker_inet_dgram_handle(typed)?;
                    let (peer_raw, payload, dgram_flags) = handle
                        .with_entry(|entry| entry.recvfrom(&self.wait_cx(), buf.len() as u32))?;
                    let copied = buf.len().min(payload.len());
                    buf[..copied].copy_from_slice(&payload[..copied]);
                    if let Some(source_addr) = source_addr {
                        *source_addr = Some(inet_listener_wire_to_socket_address(peer_raw)?);
                    }
                    let truncated = (dgram_flags
                        & litebox_common_linux::cwfd::fd_token_protocol::INET_DGRAM_RECV_FLAG_TRUNC)
                        != 0;
                    Ok(if truncated {
                        copied.saturating_add(1)
                    } else {
                        copied
                    })
                })
                .unwrap_or(Err(Errno::EBADF)),
            // Broker-backed AF_UNIX SOCK_STREAM named socket. Like the
            // socketpair, SCM_RIGHTS arrive in-band as LBFD frames on a
            // byte stream; `recv_deframed` keeps a persistent reassembly
            // reader so coalesced / split frames are each surfaced with
            // their own fd tokens.
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |typed| {
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    let handle = self.broker_unix_stream_handle(typed)?;
                    let (n, tokens) =
                        handle.with_entry(|entry| entry.recv_deframed(&self.wait_cx(), buf))?;
                    received_tokens.extend(tokens);
                    Ok(n)
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketSeqPacket => self
                .try_with_broker_socket_seqpacket(sockfd, |typed| {
                    let handle = self.broker_socket_seqpacket_handle(typed)?;
                    let recv_len = if flags.contains(ReceiveFlags::TRUNC) {
                        u32::MAX
                    } else {
                        buf.len() as u32
                    };
                    let (payload, packet_flags, tokens) =
                        handle.with_entry(|entry| entry.recv(&self.wait_cx(), recv_len))?;
                    received_tokens.extend(tokens);
                    let copied = buf.len().min(payload.len());
                    buf[..copied].copy_from_slice(&payload[..copied]);
                    if flags.contains(ReceiveFlags::TRUNC) {
                        return Ok(payload.len());
                    }
                    Ok(
                        if super::broker_socket_seqpacket::recv_truncated(packet_flags) {
                            copied.saturating_add(1)
                        } else {
                            copied
                        },
                    )
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketDgram => self
                .try_with_broker_socket_dgram(sockfd, |typed| {
                    let handle = self.broker_socket_dgram_handle(typed)?;
                    let recv_len = if flags.contains(ReceiveFlags::TRUNC) {
                        u32::MAX
                    } else {
                        buf.len() as u32
                    };
                    let (src, payload, dgram_flags, tokens) =
                        handle.with_entry(|entry| entry.recvfrom(&self.wait_cx(), recv_len))?;
                    received_tokens.extend(tokens);
                    let copied = buf.len().min(payload.len());
                    buf[..copied].copy_from_slice(&payload[..copied]);
                    if let Some(source_addr) = source_addr {
                        *source_addr = Some(SocketAddress::Unix(src));
                    }
                    if flags.contains(ReceiveFlags::TRUNC) {
                        return Ok(payload.len());
                    }
                    Ok(if super::broker_socket_dgram::recv_truncated(dgram_flags) {
                        copied.saturating_add(1)
                    } else {
                        copied
                    })
                })
                .unwrap_or(Err(Errno::EBADF)),
            // inet-listener / inet-raw have no recv fast path; preserve the
            // historical fall-through to `with_socket`. AF_UNIX / worker-local
            // inet are dispatched by `with_socket`.
            SocketIoClass::BrokerInetListener
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => {
                let (size, addr) = {
                    let buf: core::cell::RefCell<&mut [u8]> = core::cell::RefCell::new(buf);
                    self.files.borrow().with_socket(
                        &self.global,
                        sockfd,
                        |fd| {
                            #[cfg(feature = "worker_local_inet")]
                            {
                                let mut addr = None;
                                let size = self.global.receive(
                                    &self.wait_cx(),
                                    fd,
                                    &mut buf.borrow_mut(),
                                    flags,
                                    if want_source { Some(&mut addr) } else { None },
                                )?;
                                let src_addr = addr.map(SocketAddress::Inet);
                                Ok((size, src_addr))
                            }
                            #[cfg(not(feature = "worker_local_inet"))]
                            {
                                let _ = fd;
                                Err(Errno::ENOTSOCK)
                            }
                        },
                        |entry| {
                            let mut addr = None;
                            let size = entry.recvfrom(
                                &self.wait_cx(),
                                &mut buf.borrow_mut(),
                                flags,
                                if want_source { Some(&mut addr) } else { None },
                                received_fds,
                                received_tokens,
                            )?;
                            let src_addr = addr.map(SocketAddress::Unix);
                            Ok((size, src_addr))
                        },
                    )?
                };

                if !flags.contains(ReceiveFlags::TRUNC) {
                    let len = buf.len();
                    assert!(size <= len, "{size} should be smaller than {len}");
                }

                if let (Some(source_addr), Some(addr)) = (source_addr, addr) {
                    *source_addr = Some(addr);
                }
                Ok(size)
            }
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        }
    }

    pub(crate) fn sys_setsockopt(
        &self,
        sockfd: i32,
        level: u32,
        optname: u32,
        optval: ConstPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        if passthrough_sockopt_value(level, optname).is_some() {
            let _val: u32 = super::read_from_user(optval, optlen)?;
            return Ok(());
        }
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            if level == 41 {
                return Errno::ENOPROTOOPT;
            }
            log_unsupported!("setsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        });
        match optname {
            Ok(name) => self.do_setsockopt(sockfd, name, optval, optlen),
            Err(Errno::ENOPROTOOPT) => Ok(()),
            Err(e) => Err(e),
        }
    }
    fn do_setsockopt(
        &self,
        sockfd: u32,
        optname: SocketOptionName,
        optval: ConstPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        // Netlink socket: ignore setsockopt.
        if self.netlink_sockets.borrow().contains_key(&sockfd) {
            return Ok(());
        }
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        let broker_sockopt = |optname| match optname {
            SocketOptionName::Socket(
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::REUSEPORT
                | SocketOption::BROADCAST
                | SocketOption::KEEPALIVE,
            ) => self
                .global
                .setsockopt_common(optname, optval, optlen, |_sopt, _value| Ok(())),
            SocketOptionName::Socket(SocketOption::RCVBUF | SocketOption::SNDBUF)
            | SocketOptionName::TCP(TcpOption::NODELAY | TcpOption::CORK) => {
                let _val: u32 = super::read_from_user(optval, optlen)?;
                Ok(())
            }
            _ => Err(Errno::ENOPROTOOPT),
        };
        let class = self.socket_io_class_of(sockfd)?;
        match class {
            SocketIoClass::BrokerInetDgram => self
                .try_with_broker_inet_dgram(sockfd, |typed| {
                    let value = optval.to_owned_slice(optlen).ok_or(Errno::EFAULT)?;
                    let (level, name) = socket_option_name_to_raw(optname);
                    let handle = self.broker_inet_dgram_handle(typed)?;
                    handle.with_entry(|entry| entry.setsockopt(level, name, &value))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketPair => self
                .try_with_broker_sp(sockfd, |_typed| broker_sockopt(optname))
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerTcpConn => self
                .try_with_broker_tcp_conn(sockfd, |typed| {
                    if matches!(
                        optname,
                        SocketOptionName::Socket(SocketOption::RCVBUF | SocketOption::SNDBUF)
                    ) {
                        let _val: u32 = super::read_from_user(optval, optlen)?;
                        return Ok(());
                    }
                    let (level, raw_optname) = socket_option_raw(optname);
                    let value = optval.to_owned_slice(optlen).ok_or(Errno::EFAULT)?;
                    let handle = self.broker_tcp_conn_handle(typed)?;
                    handle.with_entry(|entry| entry.setsockopt(level, raw_optname, &value))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetListener => self
                .try_with_broker_inet_listener(sockfd, |typed| {
                    if matches!(
                        optname,
                        SocketOptionName::IPv6(litebox_common_linux::Ipv6Option::V6ONLY)
                    ) {
                        let _val: u32 = super::read_from_user(optval, optlen)?;
                        return Ok(());
                    }
                    let value = optval.to_owned_slice(optlen).ok_or(Errno::EFAULT)?;
                    let (level, raw_optname) = socket_option_raw(optname);
                    let handle = self.broker_inet_listener_handle(typed)?;
                    handle.with_entry(|entry| entry.setsockopt(level, raw_optname, &value))
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |_typed| broker_sockopt(optname))
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketDgram
            | SocketIoClass::BrokerSocketSeqPacket
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => self.files.borrow().with_socket(
                &self.global,
                sockfd,
                |fd| {
                    #[cfg(feature = "worker_local_inet")]
                    {
                        self.global.setsockopt(fd, optname, optval, optlen)
                    }
                    #[cfg(not(feature = "worker_local_inet"))]
                    {
                        let _ = fd;
                        Err(Errno::ENOTSOCK)
                    }
                },
                |file| file.setsockopt(&self.global, optname, optval, optlen),
            ),
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `getsockopt`
    pub(crate) fn sys_getsockopt(
        &self,
        sockfd: i32,
        level: u32,
        optname: u32,
        optval: MutPtr<u8>,
        optlen: MutPtr<u32>,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        if let Some(value) = passthrough_sockopt_value(level, optname) {
            let len = optlen.read_at_offset(0).ok_or(Errno::EFAULT)?;
            if len > i32::MAX as u32 {
                return Err(Errno::EINVAL);
            }
            let new_len = super::write_to_user(value, optval, len)?;
            optlen
                .write_at_offset(0, new_len.truncate())
                .ok_or(Errno::EFAULT)?;
            return Ok(());
        }
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            log_unsupported!("getsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        })?;
        let len = optlen.read_at_offset(0).ok_or(Errno::EFAULT)?;
        if len > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        let new_len = self.do_getsockopt(sockfd, optname, optval, len)?;
        optlen
            .write_at_offset(0, new_len.truncate())
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
        optval: MutPtr<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        // Netlink socket: return reasonable defaults.
        if self.netlink_sockets.borrow().contains_key(&sockfd) {
            // reason: unsupported variants intentionally share this fallback path.
            #[allow(clippy::wildcard_enum_match_arm)]
            let val: u32 = match optname {
                SocketOptionName::Socket(SocketOption::ERROR) => 0,
                SocketOptionName::Socket(SocketOption::RCVBUF)
                | SocketOptionName::Socket(SocketOption::SNDBUF) => 212992,
                _ => return Ok(0),
            };
            if len >= 4 {
                let ptr = MutPtr::<u32>::from_usize(optval.as_usize());
                ptr.write_at_offset(0, val);
                return Ok(4);
            }
            return Ok(0);
        }
        // reason: unsupported variants intentionally share this fallback path.
        #[allow(clippy::wildcard_enum_match_arm)]
        let broker_getsockopt = |optname| match optname {
            SocketOptionName::Socket(
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO | SocketOption::LINGER,
            ) => self
                .global
                .getsockopt_common(optname, optval, len, |_sopt| {
                    SocketOptionValue::Timeout(None)
                }),
            SocketOptionName::Socket(
                SocketOption::REUSEADDR
                | SocketOption::REUSEPORT
                | SocketOption::KEEPALIVE
                | SocketOption::BROADCAST,
            ) => self
                .global
                .getsockopt_common(optname, optval, len, |_sopt| SocketOptionValue::U32(0)),
            SocketOptionName::Socket(SocketOption::ERROR) => {
                super::write_to_user(0u32, optval, len)
            }
            SocketOptionName::Socket(SocketOption::TYPE) => {
                super::write_to_user(SockType::Stream as u32, optval, len)
            }
            SocketOptionName::Socket(SocketOption::RCVBUF | SocketOption::SNDBUF) => {
                super::write_to_user(64u32 * 1024, optval, len)
            }
            SocketOptionName::TCP(TcpOption::NODELAY | TcpOption::CORK) => {
                super::write_to_user(0u32, optval, len)
            }
            _ => Err(Errno::ENOPROTOOPT),
        };
        let class = self.socket_io_class_of(sockfd)?;
        // SO_TYPE is fixed by the socket's class, not by broker per-fd state.
        // BrokerTcpConn/InetListener/InetDgram/InetRaw otherwise delegate
        // getsockopt to the broker, whose `ensure_supported_sockopt` rejects
        // SO_TYPE with EOPNOTSUPP; the dgram/seqpacket/raw shim arms route to
        // `with_socket`, which returns ENOTSOCK without `worker_local_inet`.
        // Either way libuv's `uv_guess_handle` on an SCM-passed socket then
        // gets an error, returns UV_UNKNOWN_HANDLE, and node refuses to adopt
        // the fd — stalling the VS Code exthost connection. Answer SO_TYPE
        // locally from the socket class. Exhaustive over `SocketIoClass` (no
        // wildcard) so a new class forces a deliberate decision here.
        if matches!(optname, SocketOptionName::Socket(SocketOption::TYPE)) {
            let sock_type = match class {
                SocketIoClass::BrokerSocketDgram | SocketIoClass::BrokerInetDgram => {
                    Some(SockType::Datagram)
                }
                SocketIoClass::BrokerSocketSeqPacket => Some(SockType::SeqPacket),
                SocketIoClass::BrokerInetRaw => Some(SockType::Raw),
                SocketIoClass::BrokerSocketPair
                | SocketIoClass::BrokerUnixStream
                | SocketIoClass::BrokerTcpConn
                | SocketIoClass::BrokerInetListener => Some(SockType::Stream),
                // Shim-local sockets resolve SO_TYPE through their own
                // getsockopt below; non-sockets fall through to ENOTSOCK.
                SocketIoClass::WithSocket | SocketIoClass::NotASocket => None,
            };
            if let Some(sock_type) = sock_type {
                return super::write_to_user(sock_type as u32, optval, len);
            }
        }
        match class {
            SocketIoClass::BrokerInetDgram => self
                .try_with_broker_inet_dgram(sockfd, |typed| {
                    let (level, name) = socket_option_name_to_raw(optname);
                    let handle = self.broker_inet_dgram_handle(typed)?;
                    let value = handle.with_entry(|entry| entry.getsockopt(level, name, len))?;
                    let copy_len = value.len().min(len as usize);
                    optval
                        .copy_from_slice(0, &value[..copy_len])
                        .ok_or(Errno::EFAULT)?;
                    Ok(copy_len)
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketPair => self
                .try_with_broker_sp(sockfd, |_typed| broker_getsockopt(optname))
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerTcpConn => self
                .try_with_broker_tcp_conn(sockfd, |typed| {
                    if matches!(
                        optname,
                        SocketOptionName::Socket(SocketOption::RCVBUF | SocketOption::SNDBUF)
                    ) {
                        return super::write_to_user(64u32 * 1024, optval, len);
                    }
                    let (level, raw_optname) = socket_option_raw(optname);
                    let handle = self.broker_tcp_conn_handle(typed)?;
                    let value =
                        handle.with_entry(|entry| entry.getsockopt(level, raw_optname, len))?;
                    let write_len = value.len().min(len as usize);
                    optval
                        .write_slice_at_offset(0, &value[..write_len])
                        .ok_or(Errno::EFAULT)?;
                    Ok(write_len)
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerInetListener => self
                .try_with_broker_inet_listener(sockfd, |typed| {
                    let (level, raw_optname) = socket_option_raw(optname);
                    let handle = self.broker_inet_listener_handle(typed)?;
                    let value =
                        handle.with_entry(|entry| entry.getsockopt(level, raw_optname, len))?;
                    let write_len = value.len().min(len as usize);
                    optval
                        .write_slice_at_offset(0, &value[..write_len])
                        .ok_or(Errno::EFAULT)?;
                    Ok(write_len)
                })
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerUnixStream => self
                .try_with_broker_unix_stream(sockfd, |_typed| broker_getsockopt(optname))
                .unwrap_or(Err(Errno::EBADF)),
            SocketIoClass::BrokerSocketDgram
            | SocketIoClass::BrokerSocketSeqPacket
            | SocketIoClass::BrokerInetRaw
            | SocketIoClass::WithSocket => self.files.borrow().with_socket(
                &self.global,
                sockfd,
                |fd| {
                    #[cfg(feature = "worker_local_inet")]
                    {
                        self.global.getsockopt(fd, optname, optval, len)
                    }
                    #[cfg(not(feature = "worker_local_inet"))]
                    {
                        let _ = fd;
                        Err(Errno::ENOTSOCK)
                    }
                },
                |file| file.getsockopt(&self.global, optname, optval, len),
            ),
            SocketIoClass::NotASocket => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `getsockname`
    pub(crate) fn sys_getsockname(
        &self,
        sockfd: i32,
        addr: MutPtr<u8>,
        addrlen: MutPtr<u32>,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        // Netlink socket: write sockaddr_nl directly.
        if self.netlink_sockets.borrow().contains_key(&sockfd) {
            // struct sockaddr_nl { sa_family(2) + nl_pad(2) + nl_pid(4) + nl_groups(4) } = 12
            let mut sa = [0u8; 12];
            sa[0..2].copy_from_slice(&16u16.to_ne_bytes()); // sa_family = AF_NETLINK
            let pid = u32::try_from(self.pid).unwrap_or(0);
            sa[4..8].copy_from_slice(&pid.to_ne_bytes()); // nl_pid
            let user_len = addrlen.read_at_offset(0).ok_or(Errno::EFAULT)?;
            let copy_len = (user_len as usize).min(sa.len());
            for i in 0..copy_len {
                addr.write_at_offset(i as isize, sa[i]);
            }
            addrlen.write_at_offset(0, 12u32);
            return Ok(());
        }
        let sockaddr = self.do_getsockname(sockfd)?;
        let is_inet6 = self.inet6_fds.borrow().contains(&sockfd);
        if is_inet6 {
            write_sockaddr_v6_mapped_to_user(sockaddr, addr, addrlen)
        } else {
            write_sockaddr_to_user(sockaddr, addr, addrlen)
        }
    }
    fn do_getsockname(&self, sockfd: u32) -> Result<SocketAddress, Errno> {
        // Netlink socket: return a dummy address.
        if self.netlink_sockets.borrow().contains_key(&sockfd) {
            return Ok(SocketAddress::default());
        }
        if let Some(result) = self.try_with_broker_sp(sockfd, |_typed| {
            Ok(SocketAddress::Unix(super::unix::UnixSocketAddr::Unnamed))
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_socket_dgram(sockfd, |typed| {
            let handle = self.broker_socket_dgram_handle(typed)?;
            handle
                .with_entry(|entry| entry.getsockname())
                .map(SocketAddress::Unix)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_unix_stream(sockfd, |typed| {
            let handle = self.broker_unix_stream_handle(typed)?;
            handle
                .with_entry(|entry| entry.getsockname())
                .map(SocketAddress::Unix)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_socket_seqpacket(sockfd, |typed| {
            let handle = self.broker_socket_seqpacket_handle(typed)?;
            handle
                .with_entry(|entry| entry.getsockname())
                .map(SocketAddress::Unix)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_tcp_conn(sockfd, |typed| {
            let handle = self.broker_tcp_conn_handle(typed)?;
            handle
                .with_entry(|entry| entry.getsockname())
                .and_then(inet_listener_wire_to_socket_address)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_inet_listener(sockfd, |typed| {
            let handle = self.broker_inet_listener_handle(typed)?;
            handle
                .with_entry(|entry| entry.getsockname())
                .and_then(inet_listener_wire_to_socket_address)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_inet_dgram(sockfd, |typed| {
            let handle = self.broker_inet_dgram_handle(typed)?;
            handle
                .with_entry(|entry| entry.getsockname())
                .and_then(inet_listener_wire_to_socket_address)
        }) {
            return result;
        }
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                #[cfg(feature = "worker_local_inet")]
                {
                    Ok(SocketAddress::Inet(
                        self.global.net.lock().get_local_addr(fd)?,
                    ))
                }
                #[cfg(not(feature = "worker_local_inet"))]
                {
                    let _ = fd;
                    Err(Errno::ENOTSOCK)
                }
            },
            |file| Ok(SocketAddress::Unix(file.get_local_addr())),
        )
    }

    /// Handle syscall `getpeername`
    pub(crate) fn sys_getpeername(
        &self,
        sockfd: i32,
        addr: MutPtr<u8>,
        addrlen: MutPtr<u32>,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = self.do_getpeername(sockfd)?;
        let is_inet6 = self.inet6_fds.borrow().contains(&sockfd);
        if is_inet6 {
            write_sockaddr_v6_mapped_to_user(sockaddr, addr, addrlen)
        } else {
            write_sockaddr_to_user(sockaddr, addr, addrlen)
        }
    }
    fn do_getpeername(&self, sockfd: u32) -> Result<SocketAddress, Errno> {
        if let Some(result) = self.try_with_broker_sp(sockfd, |_typed| {
            Ok(SocketAddress::Unix(super::unix::UnixSocketAddr::Unnamed))
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_socket_dgram(sockfd, |typed| {
            let handle = self.broker_socket_dgram_handle(typed)?;
            handle
                .with_entry(|entry| entry.getpeername())
                .map(SocketAddress::Unix)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_unix_stream(sockfd, |typed| {
            let handle = self.broker_unix_stream_handle(typed)?;
            handle
                .with_entry(|entry| entry.getpeername())
                .map(SocketAddress::Unix)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_socket_seqpacket(sockfd, |typed| {
            let handle = self.broker_socket_seqpacket_handle(typed)?;
            handle
                .with_entry(|entry| entry.getpeername())
                .map(SocketAddress::Unix)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_tcp_conn(sockfd, |typed| {
            let handle = self.broker_tcp_conn_handle(typed)?;
            handle
                .with_entry(|entry| entry.getpeername())
                .and_then(inet_listener_wire_to_socket_address)
        }) {
            return result;
        }
        if let Some(result) = self.try_with_broker_inet_dgram(sockfd, |typed| {
            let handle = self.broker_inet_dgram_handle(typed)?;
            handle
                .with_entry(|entry| entry.getpeername())
                .and_then(inet_listener_wire_to_socket_address)
        }) {
            return result;
        }
        self.files.borrow().with_socket(
            &self.global,
            sockfd,
            |fd| {
                #[cfg(feature = "worker_local_inet")]
                {
                    Ok(SocketAddress::Inet(
                        self.global.net.lock().get_remote_addr(fd)?,
                    ))
                }
                #[cfg(not(feature = "worker_local_inet"))]
                {
                    let _ = fd;
                    Err(Errno::ENOTSOCK)
                }
            },
            |file| {
                file.get_peer_addr()
                    .ok_or(Errno::ENOTCONN)
                    .map(SocketAddress::Unix)
            },
        )
    }
}

#[cfg(target_arch = "x86")]
impl<FS: ShimFS> Task<FS> {
    pub(crate) fn sys_socketcall(&self, call: i32, args: ConstPtr<usize>) -> Result<usize, Errno> {
        use crate::ToSyscallResult;
        use litebox_common_linux::SocketcallType;
        macro_rules! parse_socketcall_args {
            ($nargs:literal => $func:ident { $($field:ident: $tt:tt),* $(,)? }) => {{
                let args = args.to_owned_slice($nargs).ok_or(Errno::EFAULT)?;
                self.$func (
                    $(parse_socketcall_args!(@convert args $tt )),*
                ).to_syscall_result()
            }};

            // Convert with pointer marker - use from_usize for pointer types
            (@convert $args:ident [ $idx:literal ]) => {
                <_ as litebox_common_linux::ReinterpretUsizeAsPtr<_>>::reinterpret_usize_as_ptr($args[$idx])
            };

            // Convert without marker - use reinterpret_truncated_from_usize for regular types
            (@convert $args:ident $idx:literal) => {
                litebox_common_linux::ReinterpretTruncatedFromUsize::reinterpret_truncated_from_usize($args[$idx])
            };

            (@convert $args:ident $v:ident) => {
                $v
            };
        }

        let socketcall_type = SocketcallType::try_from(call).map_err(|_| Errno::EINVAL)?;
        match socketcall_type {
            SocketcallType::Socket => {
                parse_socketcall_args!(3 => sys_socket {
                    domain: 0,
                    type_and_flags: 1,
                    protocol: 2,
                })
            }
            SocketcallType::Socketpair => {
                parse_socketcall_args!(4 => sys_socketpair {
                    domain: 0,
                    type_and_flags: 1,
                    protocol: 2,
                    sv: [ 3 ],
                })
            }
            SocketcallType::Bind => {
                parse_socketcall_args!(3 => sys_bind {
                    sockfd: 0,
                    sockaddr: [ 1 ],
                    addrlen: 2,
                })
            }
            SocketcallType::Connect => {
                parse_socketcall_args!(3 => sys_connect {
                    sockfd: 0,
                    sockaddr: [ 1 ],
                    addrlen: 2,
                })
            }
            SocketcallType::Listen => {
                parse_socketcall_args!(2 => sys_listen {
                    sockfd: 0,
                    backlog: 1,
                })
            }
            SocketcallType::Shutdown => {
                parse_socketcall_args!(2 => sys_shutdown {
                    sockfd: 0,
                    how: 1,
                })
            }
            SocketcallType::Accept => {
                let flags = SockFlags::empty();
                parse_socketcall_args!(3 => sys_accept {
                    sockfd: 0,
                    addr: [ 1 ],
                    addrlen: [ 2 ],
                    flags: flags,
                })
            }
            SocketcallType::Accept4 => {
                parse_socketcall_args!(4 => sys_accept {
                    sockfd: 0,
                    addr: [ 1 ],
                    addrlen: [ 2 ],
                    flags: 3,
                })
            }
            SocketcallType::Send => {
                let addr = None;
                let addrlen = 0;
                parse_socketcall_args!(4 => sys_sendto {
                    sockfd: 0,
                    buf: [ 1 ],
                    len: 2,
                    flags: 3,
                    addr: addr,
                    addrlen: addrlen,
                })
            }
            SocketcallType::Sendto => {
                parse_socketcall_args!(6 => sys_sendto {
                    sockfd: 0,
                    buf: [ 1 ],
                    len: 2,
                    flags: 3,
                    addr: [ 4 ],
                    addrlen: 5,
                })
            }
            SocketcallType::Recv => {
                let addr = None;
                let addrlen = MutPtr::from_usize(0);
                parse_socketcall_args!(4 => sys_recvfrom {
                    sockfd: 0,
                    buf: [ 1 ],
                    len: 2,
                    flags: 3,
                    addr: addr,
                    addrlen: addrlen,
                })
            }
            SocketcallType::Recvfrom => {
                parse_socketcall_args!(6 => sys_recvfrom {
                    sockfd: 0,
                    buf: [ 1 ],
                    len: 2,
                    flags: 3,
                    addr: [ 4 ],
                    addrlen: [ 5 ],
                })
            }
            SocketcallType::GetSockname => {
                parse_socketcall_args!(3 => sys_getsockname {
                    sockfd: 0,
                    addr: [ 1 ],
                    addrlen: [ 2 ],
                })
            }
            SocketcallType::GetPeername => {
                parse_socketcall_args!(3 => sys_getpeername {
                    sockfd: 0,
                    addr: [ 1 ],
                    addrlen: [ 2 ],
                })
            }
            SocketcallType::Setsockopt => {
                parse_socketcall_args!(5 => sys_setsockopt {
                    sockfd: 0,
                    level: 1,
                    optname: 2,
                    optval: [ 3 ],
                    optlen: 4,
                })
            }
            SocketcallType::Getsockopt => {
                parse_socketcall_args!(5 => sys_getsockopt {
                    sockfd: 0,
                    level: 1,
                    optname: 2,
                    optval: [ 3 ],
                    optlen: [ 4 ],
                })
            }
            SocketcallType::Sendmsg => {
                parse_socketcall_args!(3 => sys_sendmsg {
                    sockfd: 0,
                    msg: [ 1 ],
                    flags: 2,
                })
            }
            SocketcallType::Recvmsg => {
                parse_socketcall_args!(3 => sys_recvmsg {
                    fd: 0,
                    msg: [ 1 ],
                    flags: 2,
                })
            }
            _ => {
                log_unsupported!("socketcall type {socketcall_type:?} is not supported");
                Err(Errno::EINVAL)
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use alloc::string::ToString as _;
    use litebox::platform::RawConstPointer as _;
    use litebox::utils::TruncateExt as _;
    use litebox_common_linux::{
        AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption,
        SocketOptionName, TcpOption, errno::Errno,
    };

    use super::SocketAddress;
    use crate::{ConstPtr, MutPtr, syscalls::tests::init_platform};

    extern crate alloc;
    extern crate std;

    // Compile-time layout check: UserMsgHdr must match Linux's struct user_msghdr.
    const _USER_MSG_HDR_SIZE: () = assert!(
        core::mem::size_of::<litebox_common_linux::UserMsgHdr<crate::Platform>>()
            == core::mem::size_of::<libc::msghdr>()
    );

    const TUN_IP_ADDR: [u8; 4] = [10, 0, 0, 2];
    const TUN_IP_ADDR_STR: &str = "10.0.0.2";
    const TUN_DEVICE_NAME: &str = "tun99";
    const SERVER_PORT: u16 = 8080;
    const CLIENT_PORT: u16 = 8081;

    fn close_socket(task: &crate::Task<crate::DefaultFS>, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
    }

    /// Helper to read SO_ERROR from a socket via getsockopt.
    /// Returns the errno integer value (0 means no error).
    fn get_so_error(task: &crate::Task<crate::DefaultFS>, sockfd: u32) -> u32 {
        let mut optval: u32 = 0xDEAD;
        let len = task
            .do_getsockopt(
                sockfd,
                SocketOptionName::Socket(SocketOption::ERROR),
                MutPtr::from_usize((&raw mut optval).cast::<u8>() as usize),
                core::mem::size_of::<u32>().truncate(),
            )
            .expect("getsockopt SO_ERROR failed");
        assert_eq!(len, core::mem::size_of::<u32>());
        optval
    }

    pub(super) fn get_so_peercred(
        task: &crate::Task<crate::DefaultFS>,
        sockfd: u32,
    ) -> litebox_common_linux::Ucred {
        let mut peercred = litebox_common_linux::Ucred {
            pid: u32::MAX,
            uid: 0,
            gid: 0,
        };
        let len = task
            .do_getsockopt(
                sockfd,
                SocketOptionName::Socket(SocketOption::PEERCRED),
                MutPtr::from_usize((&raw mut peercred).cast::<u8>() as usize),
                core::mem::size_of::<litebox_common_linux::Ucred>().truncate(),
            )
            .expect("getsockopt SO_PEERCRED failed");
        assert_eq!(len, core::mem::size_of::<litebox_common_linux::Ucred>());
        peercred
    }

    pub(super) fn assert_ucred_eq(
        actual: litebox_common_linux::Ucred,
        expected: litebox_common_linux::Ucred,
    ) {
        assert_eq!(actual.pid, expected.pid);
        assert_eq!(actual.uid, expected.uid);
        assert_eq!(actual.gid, expected.gid);
    }

    pub(super) fn unconnected_peercred() -> litebox_common_linux::Ucred {
        litebox_common_linux::Ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        }
    }

    fn epoll_add(
        task: &crate::Task<crate::DefaultFS>,
        epfd: i32,
        target_fd: u32,
        events: litebox::event::Events,
    ) {
        let ev = litebox_common_linux::EpollEvent {
            events: events.bits(),
            data: u64::from(target_fd),
        };
        let ev_ptr = (&raw const ev).cast::<litebox_common_linux::EpollEvent>();
        let ev_const = crate::ConstPtr::from_usize(ev_ptr as usize);
        task.sys_epoll_ctl(
            epfd,
            litebox_common_linux::EpollOp::EpollCtlAdd,
            i32::try_from(target_fd).unwrap(),
            ev_const,
        )
        .expect("epoll_ctl add server failed");
    }

    fn epoll_wait(
        task: &crate::Task<crate::DefaultFS>,
        epfd: i32,
        events: &mut [litebox_common_linux::EpollEvent],
    ) -> usize {
        let events_ptr = crate::MutPtr::from_usize(events.as_mut_ptr() as usize);
        task.sys_epoll_pwait(
            epfd,
            events_ptr,
            events.len().truncate(),
            litebox_common_linux::TimeParam::Milliseconds(-1),
            None,
            0,
        )
        .expect("epoll_wait failed")
    }

    fn epoll_wait_timeout(
        task: &crate::Task<crate::DefaultFS>,
        epfd: i32,
        events: &mut [litebox_common_linux::EpollEvent],
        timeout_ms: i32,
    ) -> usize {
        let events_ptr = crate::MutPtr::from_usize(events.as_mut_ptr() as usize);
        task.sys_epoll_pwait(
            epfd,
            events_ptr,
            events.len().truncate(),
            litebox_common_linux::TimeParam::Milliseconds(timeout_ms),
            None,
            0,
        )
        .expect("epoll_wait with timeout failed")
    }

    fn test_tcp_socket_as_server(
        task: &crate::Task<crate::DefaultFS>,
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
                        iov_base: MutPtr::from_usize(buf1.as_ptr().expose_provenance()),
                        iov_len: buf1.len(),
                    },
                    litebox_common_linux::IoVec {
                        iov_base: MutPtr::from_usize(buf2.as_ptr().expose_provenance()),
                        iov_len: buf2.len(),
                    },
                ];
                let hdr = {
                    use zerocopy::FromZeros as _;
                    let mut h = litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed();
                    h.msg_iov = ConstPtr::from_usize(iovec.as_ptr() as usize);
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
            "recvfrom" => {
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
                let n = task
                    .do_recvfrom(
                        client_fd,
                        &mut recv_buf,
                        if test_trunc {
                            ReceiveFlags::TRUNC
                        } else {
                            ReceiveFlags::empty()
                        },
                        None,
                    )
                    .expect("Failed to receive data");
                if test_trunc {
                    assert!(recv_buf.iter().all(|&b| b == 0)); // buf remains unchanged
                } else {
                    assert_eq!(recv_buf[..n], buf.as_bytes()[..n]);
                }
                assert_eq!(n, buf.len()); // even with truncation, it returns the actual length
                let _ = child_handle.join().expect("Failed to wait for client");
            }
            "recvmsg" => {
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

                let mut buf1 = [0u8; 5];
                let mut buf2 = [0u8; 16];
                let iovec = [
                    litebox_common_linux::IoVec {
                        iov_base: MutPtr::from_usize(buf1.as_mut_ptr() as usize),
                        iov_len: buf1.len(),
                    },
                    litebox_common_linux::IoVec {
                        iov_base: MutPtr::from_usize(buf2.as_mut_ptr() as usize),
                        iov_len: buf2.len(),
                    },
                ];
                let mut hdr = {
                    use zerocopy::FromZeros as _;
                    let mut h = litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed();
                    h.msg_iov = ConstPtr::from_usize(iovec.as_ptr() as usize);
                    h.msg_iovlen = iovec.len();
                    h
                };
                let n = task
                    .sys_recvmsg(
                        i32::try_from(client_fd).unwrap(),
                        MutPtr::from_usize((&raw mut hdr) as usize),
                        ReceiveFlags::empty(),
                    )
                    .expect("Failed to recvmsg");
                assert_eq!(n, buf.len());
                let combined = alloc::format!(
                    "{}{}",
                    alloc::string::String::from_utf8_lossy(&buf1),
                    alloc::string::String::from_utf8_lossy(&buf2[..buf.len() - buf1.len()])
                );
                assert_eq!(combined, buf);
                let _ = child_handle.join().expect("Failed to wait for client");
            }
            _ => panic!("Unknown option"),
        }

        close_socket(task, client_fd);
        close_socket(task, server);
    }

    fn test_tcp_socket_with_external_client(
        port: u16,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &'static str,
    ) {
        let task = init_platform(Some(TUN_DEVICE_NAME));
        test_tcp_socket_as_server(&task, TUN_IP_ADDR, port, is_nonblocking, test_trunc, option);
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
        test_tcp_socket_with_external_client(SERVER_PORT, false, false, "recvfrom");
    }

    #[test]
    fn test_tun_nonblocking_recvfrom_tcp_socket() {
        test_tcp_socket_with_external_client(SERVER_PORT, true, false, "recvfrom");
    }

    #[test]
    fn test_tun_blocking_recvfrom_tcp_socket_with_truncation() {
        test_tcp_socket_with_external_client(SERVER_PORT, false, true, "recvfrom");
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
        std::thread::sleep(core::time::Duration::from_millis(1000));

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
        let optval = ConstPtr::from_usize((&raw const linger).cast::<u8>() as usize);
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

    fn test_nonblocking_tcp_connect_epoll_then_send(epoll_add_delay: core::time::Duration) {
        const NONBLOCK_CONNECT_PORT: u16 = 8082;

        let task = init_platform(Some(TUN_DEVICE_NAME));
        let buf = "Hello, world!";

        let child_handle = std::thread::spawn(|| {
            std::process::Command::new("nc")
                .args([
                    "-w",
                    "2",
                    "-l",
                    "10.0.0.1",
                    NONBLOCK_CONNECT_PORT.to_string().as_str(),
                ])
                .output()
        });
        std::thread::sleep(core::time::Duration::from_millis(1000));

        let client_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Stream,
                SockFlags::NONBLOCK,
                0,
            )
            .expect("failed to create nonblocking client socket");
        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from([10, 0, 0, 1]),
            NONBLOCK_CONNECT_PORT,
        )));
        let err = task
            .do_connect(client_fd, server_addr)
            .expect_err("nonblocking connect should report EINPROGRESS");
        assert_eq!(err, Errno::EINPROGRESS);

        if !epoll_add_delay.is_zero() {
            std::thread::sleep(epoll_add_delay);
        }

        let epfd = task
            .sys_epoll_create(litebox_common_linux::EpollCreateFlags::empty())
            .expect("failed to create epoll");
        let epfd = i32::try_from(epfd).unwrap();
        epoll_add(
            &task,
            epfd,
            client_fd,
            litebox::event::Events::OUT | litebox::event::Events::ERR,
        );

        let mut events = [litebox_common_linux::EpollEvent { events: 0, data: 0 }; 2];
        let n = epoll_wait_timeout(&task, epfd, &mut events, 5_000);
        assert_ne!(n, 0, "timed out waiting for nonblocking connect readiness");
        assert_eq!(n, 1, "expected a single epoll event, got {n}");
        let event = &events[0];
        let event_data = event.data;
        let event_bits = event.events;
        assert_eq!(
            event_data,
            u64::from(client_fd),
            "epoll returned readiness for the wrong fd"
        );
        assert_ne!(
            event_bits & litebox::event::Events::OUT.bits(),
            0,
            "expected EPOLLOUT after connect completion, got events={event_bits:#x}",
        );

        let so_error = get_so_error(&task, client_fd);
        assert_eq!(
            so_error, 0,
            "SO_ERROR should be 0 after successful nonblocking connect, got {so_error}"
        );

        let n = task
            .do_sendto(client_fd, buf.as_bytes(), SendFlags::empty(), None)
            .expect("first send after nonblocking connect failed");
        assert_eq!(n, buf.len());

        close_socket(&task, client_fd);
        task.sys_close(epfd).expect("failed to close epoll fd");

        let output = child_handle
            .join()
            .unwrap()
            .expect("failed to wait for listener");
        let stdout = alloc::string::String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout, buf);
    }

    #[test]
    fn test_tun_nonblocking_tcp_connect_epoll_writable_then_send() {
        test_nonblocking_tcp_connect_epoll_then_send(core::time::Duration::ZERO);
    }

    #[test]
    fn test_tun_nonblocking_tcp_connect_epoll_add_after_connected() {
        test_nonblocking_tcp_connect_epoll_then_send(core::time::Duration::from_millis(200));
    }

    fn blocking_udp_server_socket(test_trunc: bool, is_nonblocking: bool) {
        let task = init_platform(Some(TUN_DEVICE_NAME));

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
        epoll_add(&task, epfd, server_fd, litebox::event::Events::IN);

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
        let mut sender_addr = None;
        let mut recv_flags = ReceiveFlags::empty();
        if test_trunc {
            recv_flags.insert(ReceiveFlags::TRUNC);
        }
        if is_nonblocking {
            let mut events = [litebox_common_linux::EpollEvent { events: 0, data: 0 }; 2];
            let n = epoll_wait(&task, epfd, &mut events);
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
        let n = task
            .do_recvfrom(
                server_fd,
                &mut recv_buf[..recv_len],
                recv_flags,
                Some(&mut sender_addr),
            )
            .expect("recvfrom failed");
        if test_trunc {
            assert_eq!(n, msg.len()); // return the actual length of the datagram rather than the received length
            assert_eq!(recv_buf[..8], msg.as_bytes()[..8]); // only part of the message is received
        } else {
            assert_eq!(n, msg.len());
            assert_eq!(recv_buf[..n], msg.as_bytes()[..n]);
        }
        let SocketAddress::Inet(sender_addr) = sender_addr.unwrap() else {
            panic!("Expected Inet socket address");
        };
        assert_eq!(sender_addr.port(), CLIENT_PORT);

        close_socket(&task, server_fd);

        child.wait().expect("Failed to wait for client");
    }

    #[test]
    fn test_tun_blocking_udp_server_socket() {
        blocking_udp_server_socket(false, false);
    }

    #[test]
    fn test_tun_nonblocking_udp_server_socket() {
        blocking_udp_server_socket(false, true);
    }

    #[test]
    fn test_tun_blocking_udp_server_socket_with_truncation() {
        blocking_udp_server_socket(true, false);
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
                MutPtr::from_usize(congestion_name.as_mut_ptr() as usize),
                congestion_name.len().truncate(),
            )
            .expect("Failed to get TCP_CONGESTION");
        assert_eq!(optlen, 4);
        assert_eq!(
            core::str::from_utf8(&congestion_name[..optlen as usize]).unwrap(),
            "none"
        );

        task.do_setsockopt(
            sockfd,
            SocketOptionName::TCP(TcpOption::CONGESTION),
            ConstPtr::from_usize(congestion_name.as_ptr() as usize),
            optlen as usize,
        )
        .expect("Failed to set TCP_CONGESTION");

        let congestion_name = b"cubic\0";
        let err = task
            .do_setsockopt(
                sockfd,
                SocketOptionName::TCP(TcpOption::CONGESTION),
                ConstPtr::from_usize(congestion_name.as_ptr() as usize),
                congestion_name.len(),
            )
            .unwrap_err();
        assert_eq!(err, Errno::EINVAL);

        let val: u32 = 1;
        let optval = ConstPtr::from_usize((&raw const val).cast::<u8>() as usize);
        task.do_setsockopt(
            sockfd,
            SocketOptionName::Socket(SocketOption::KEEPALIVE),
            optval,
            core::mem::size_of::<u32>(),
        )
        .expect("failed to set SO_KEEPALIVE");

        // Verify SO_KEEPALIVE is enabled
        let mut result: u32 = 0;
        let optval_out = MutPtr::from_usize((&raw mut result).cast::<u8>() as usize);
        let len = task
            .do_getsockopt(
                sockfd,
                SocketOptionName::Socket(SocketOption::KEEPALIVE),
                optval_out,
                core::mem::size_of::<u32>().truncate(),
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
}

#[cfg(test)]
mod unix_tests {
    use core::time::Duration;

    use alloc::{string::ToString, vec, vec::Vec};
    use litebox::{event::Events, platform::RawConstPointer};
    use litebox_common_linux::{
        AddressFamily, AtFlags, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption,
        SocketOptionName, TimeParam, errno::Errno,
    };

    use super::tests::{assert_ucred_eq, get_so_peercred, unconnected_peercred};
    use crate::{
        ConstPtr, MutPtr, Task,
        syscalls::{net::SocketAddress, tests::init_platform, unix::UnixSocketAddr},
    };

    extern crate std;

    fn create_unix_socket(task: &Task<crate::DefaultFS>, ty: SockType, flags: SockFlags) -> u32 {
        task.do_socket(AddressFamily::UNIX, ty, flags, 0).unwrap()
    }

    fn create_unix_server_socket(
        task: &Task<crate::DefaultFS>,
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

    fn close_socket(task: &crate::Task<crate::DefaultFS>, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
    }

    fn ppoll(task: &Task<crate::DefaultFS>, fd: u32, events: Events) {
        let fd = i32::try_from(fd).unwrap();
        let mut pollfd = [litebox_common_linux::Pollfd {
            fd,
            events: i16::try_from(events.bits()).unwrap(),
            revents: 0,
        }];

        let n = task
            .sys_ppoll(
                MutPtr::from_usize(pollfd.as_mut_ptr() as usize),
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
            let _ = task.sys_unlinkat(-1, server_path, AtFlags::empty());
            let _ = task.sys_unlinkat(-1, client_path, AtFlags::empty());
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
    #[ignore = "needs real broker; pathname unlink is not observable through broker mock traits"]
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

    fn unix_socketpair_bidirectional(ty: SockType, is_nonblocking: bool) {
        let task = init_platform(None);
        let mut sv_ptr = alloc::vec![0u32; 2];
        let sv_mut_ptr = MutPtr::from_usize(sv_ptr.as_mut_ptr() as usize);

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
        unix_socketpair_bidirectional(SockType::Stream, true);
    }

    #[test]
    fn test_unix_datagram_socketpair_bidirectional() {
        unix_socketpair_bidirectional(SockType::Datagram, false);
        unix_socketpair_bidirectional(SockType::Datagram, true);
    }

    fn unix_socketpair_peercred(ty: SockType) {
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(AddressFamily::UNIX, ty, SockFlags::empty(), 0)
            .expect("socketpair failed");
        let expected = task.current_ucred();

        assert_ucred_eq(get_so_peercred(&task, sock1), expected);
        assert_ucred_eq(get_so_peercred(&task, sock2), expected);

        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    #[test]
    #[ignore = "needs real broker; SO_PEERCRED/SOCK_DGRAM socketpair not exposed by broker traits"]
    fn test_unix_socketpair_peercred() {
        unix_socketpair_peercred(SockType::Stream);
        unix_socketpair_peercred(SockType::SeqPacket);
        unix_socketpair_peercred(SockType::Datagram);
    }

    #[test]
    fn test_unix_stream_connect_accept_peercred() {
        let task = init_platform(None);
        let addr = "/unix_stream_peercred.sock";
        let server_fd = create_unix_server_socket(&task, addr, SockFlags::empty()).unwrap();
        let client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let expected = task.current_ucred();

        assert_ucred_eq(get_so_peercred(&task, server_fd), unconnected_peercred());

        task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        )
        .expect("connect failed");
        let server_conn = task
            .do_accept(server_fd, None, SockFlags::empty())
            .expect("accept failed");

        assert_ucred_eq(get_so_peercred(&task, client_fd), expected);
        assert_ucred_eq(get_so_peercred(&task, server_conn), expected);

        close_socket(&task, client_fd);
        close_socket(&task, server_conn);
        close_socket(&task, server_fd);
        task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
    }

    #[test]
    #[ignore = "needs real broker; SO_PEERCRED is not exposed by broker dgram trait"]
    fn test_unix_connected_datagram_peercred() {
        let task = init_platform(None);
        let server_path = "/unix_dgram_peercred_server.sock";
        let server_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
        let client_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());

        task.do_bind(
            server_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .expect("bind failed");
        assert_ucred_eq(get_so_peercred(&task, server_fd), unconnected_peercred());

        task.do_connect(
            client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .expect("connect failed");

        assert_ucred_eq(get_so_peercred(&task, client_fd), unconnected_peercred());
        assert_ucred_eq(get_so_peercred(&task, server_fd), unconnected_peercred());

        close_socket(&task, client_fd);
        close_socket(&task, server_fd);
        task.sys_unlinkat(-1, server_path, AtFlags::empty())
            .unwrap();
    }

    #[test]
    #[ignore = "needs real broker; SO_PEERCRED is not exposed by broker socketpair trait"]
    fn test_unix_socketpair_peercred_uses_effective_ids() {
        let mut task = init_platform(None);
        task.credentials = alloc::sync::Arc::new(crate::syscalls::process::Credentials {
            uid: 1000,
            euid: 2000,
            gid: 3000,
            egid: 4000,
        });

        let (sock1, sock2) = task
            .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0)
            .expect("socketpair failed");
        let expected = task.current_ucred();

        assert_ucred_eq(get_so_peercred(&task, sock1), expected);
        assert_ucred_eq(get_so_peercred(&task, sock2), expected);

        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    fn unix_socketpair_recvmsg(ty: SockType) {
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(AddressFamily::UNIX, ty, SockFlags::empty(), 0)
            .expect("socketpair failed");

        let msg = b"recvmsg over socketpair";
        task.do_sendto(sock1, msg, SendFlags::empty(), None)
            .expect("sendto failed");

        let mut buf1 = [0u8; 7];
        let mut buf2 = [0u8; 32];
        let iovec = [
            litebox_common_linux::IoVec {
                iov_base: MutPtr::from_usize(buf1.as_mut_ptr() as usize),
                iov_len: buf1.len(),
            },
            litebox_common_linux::IoVec {
                iov_base: MutPtr::from_usize(buf2.as_mut_ptr() as usize),
                iov_len: buf2.len(),
            },
        ];
        let mut hdr = {
            use zerocopy::FromZeros as _;
            let mut h = litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed();
            h.msg_iov = ConstPtr::from_usize(iovec.as_ptr() as usize);
            h.msg_iovlen = iovec.len();
            h
        };
        let n = task
            .sys_recvmsg(
                i32::try_from(sock2).unwrap(),
                MutPtr::from_usize((&raw mut hdr) as usize),
                ReceiveFlags::empty(),
            )
            .expect("recvmsg failed");
        assert_eq!(n, msg.len());
        let msg_flags = hdr.msg_flags;
        let msg_namelen = hdr.msg_namelen;
        let msg_controllen = hdr.msg_controllen;
        assert!(msg_flags.is_empty());
        assert_eq!(msg_namelen, 0);
        assert_eq!(msg_controllen, 0);

        let mut combined = alloc::vec::Vec::new();
        combined.extend_from_slice(&buf1);
        combined.extend_from_slice(&buf2[..msg.len() - buf1.len()]);
        assert_eq!(combined.as_slice(), msg);

        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    #[test]
    fn test_unix_socketpair_recvmsg() {
        unix_socketpair_recvmsg(SockType::Stream);
    }

    #[test]
    fn test_unix_datagram_socketpair_recvmsg() {
        unix_socketpair_recvmsg(SockType::Datagram);
    }

    fn unix_socketpair_sendmsg(ty: SockType) {
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(AddressFamily::UNIX, ty, SockFlags::empty(), 0)
            .expect("socketpair failed");

        let buf1 = b"sendmsg ";
        let buf2 = b"over unix socketpair";
        let iovec = [
            litebox_common_linux::IoVec {
                iov_base: MutPtr::from_usize(buf1.as_ptr() as usize),
                iov_len: buf1.len(),
            },
            litebox_common_linux::IoVec {
                iov_base: MutPtr::from_usize(buf2.as_ptr() as usize),
                iov_len: buf2.len(),
            },
        ];
        let hdr = {
            use zerocopy::FromZeros as _;
            let mut h = litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed();
            h.msg_iov = ConstPtr::from_usize(iovec.as_ptr() as usize);
            h.msg_iovlen = iovec.len();
            h
        };
        let sent = task
            .do_sendmsg(sock1, &hdr, SendFlags::empty())
            .expect("sendmsg failed");
        assert_eq!(sent, buf1.len() + buf2.len());

        let mut recv = [0u8; 64];
        let received = task
            .do_recvfrom(sock2, &mut recv, ReceiveFlags::empty(), None)
            .expect("recvfrom failed");
        assert_eq!(received, sent);
        assert_eq!(
            &recv[..received],
            &[buf1.as_slice(), buf2.as_slice()].concat()
        );

        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    #[test]
    fn test_unix_socketpair_sendmsg() {
        unix_socketpair_sendmsg(SockType::Stream);
    }

    #[test]
    fn test_unix_datagram_socketpair_sendmsg() {
        unix_socketpair_sendmsg(SockType::Datagram);
    }

    #[test]
    fn test_sendmsg_allows_zero_iovecs_for_unix_datagram() {
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(
                AddressFamily::UNIX,
                SockType::Datagram,
                SockFlags::NONBLOCK,
                0,
            )
            .expect("socketpair failed");

        let hdr = {
            use zerocopy::FromZeros as _;
            litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed()
        };
        let sent = task
            .do_sendmsg(sock1, &hdr, SendFlags::empty())
            .expect("zero-iovec sendmsg failed");
        assert_eq!(sent, 0);

        let mut recv = [0u8; 1];
        let received = task
            .do_recvfrom(sock2, &mut recv, ReceiveFlags::DONTWAIT, None)
            .expect("recvfrom failed");
        assert_eq!(received, 0);

        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    #[test]
    fn test_sendmsg_zero_iovecs_is_noop_for_unix_stream() {
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(
                AddressFamily::UNIX,
                SockType::Stream,
                SockFlags::NONBLOCK,
                0,
            )
            .expect("socketpair failed");

        let hdr = {
            use zerocopy::FromZeros as _;
            litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed()
        };
        let sent = task
            .do_sendmsg(sock1, &hdr, SendFlags::empty())
            .expect("zero-iovec sendmsg failed");
        assert_eq!(sent, 0);

        let mut recv = [0u8; 1];
        let err = task
            .do_recvfrom(sock2, &mut recv, ReceiveFlags::DONTWAIT, None)
            .expect_err("zero-length stream send should not enqueue data");
        assert_eq!(err, Errno::EAGAIN);

        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    #[test]
    fn test_sendmsg_zero_iovecs_unconnected_unix_stream_returns_enotconn() {
        let task = init_platform(None);
        let sock = create_unix_socket(&task, SockType::Stream, SockFlags::NONBLOCK);

        let hdr = {
            use zerocopy::FromZeros as _;
            litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed()
        };
        let err = task
            .do_sendmsg(sock, &hdr, SendFlags::empty())
            .expect_err("unconnected stream sendmsg should fail");
        assert_eq!(err, Errno::ENOTCONN);

        close_socket(&task, sock);
    }

    #[test]
    fn test_sendmsg_zero_iovecs_delivers_empty_unix_seqpacket_record() {
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(
                AddressFamily::UNIX,
                SockType::SeqPacket,
                SockFlags::NONBLOCK,
                0,
            )
            .expect("socketpair failed");

        let hdr = {
            use zerocopy::FromZeros as _;
            litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed()
        };
        let sent = task
            .do_sendmsg(sock1, &hdr, SendFlags::empty())
            .expect("zero-iovec sendmsg failed");
        assert_eq!(sent, 0);

        let mut recv = [0u8; 1];
        let received = task
            .do_recvfrom(sock2, &mut recv, ReceiveFlags::DONTWAIT, None)
            .expect("zero-length seqpacket record should be delivered");
        assert_eq!(received, 0);

        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    #[test]
    #[ignore = "needs real broker; broker socket traits do not carry SCM_RIGHTS ancillary data"]
    fn test_sendmsg_rejects_ancillary_data_on_inet_socket() {
        // Ancillary data on inet sockets should still be rejected.
        let task = init_platform(None);
        let (sock1, sock2) = task
            .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0)
            .expect("socketpair failed");

        // Build a valid SCM_RIGHTS cmsg with the fd of sock2.
        let fd_to_pass = i32::try_from(sock2).unwrap();
        let hdr_size = core::mem::size_of::<litebox_common_linux::CmsgHdr>();
        let aligned_hdr = litebox_common_linux::cmsg_align(hdr_size);
        let cmsg_hdr = litebox_common_linux::CmsgHdr {
            cmsg_len: litebox_common_linux::cmsg_len(core::mem::size_of::<i32>()),
            cmsg_level: 1, // SOL_SOCKET
            cmsg_type: litebox_common_linux::SCM_RIGHTS,
        };
        let mut control_buf =
            vec![0u8; litebox_common_linux::cmsg_space(core::mem::size_of::<i32>())];
        // Write the cmsghdr.
        control_buf[..hdr_size].copy_from_slice(zerocopy::IntoBytes::as_bytes(&cmsg_hdr));
        // Write the fd.
        control_buf[aligned_hdr..aligned_hdr + core::mem::size_of::<i32>()]
            .copy_from_slice(&fd_to_pass.to_ne_bytes());

        let byte = b"x";
        let iovec = [litebox_common_linux::IoVec {
            iov_base: MutPtr::from_usize(byte.as_ptr() as usize),
            iov_len: 1,
        }];
        let send_hdr = {
            use zerocopy::FromZeros as _;
            let mut h = litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed();
            h.msg_iov = ConstPtr::from_usize(iovec.as_ptr() as usize);
            h.msg_iovlen = iovec.len();
            h.msg_control = ConstPtr::from_usize(control_buf.as_ptr() as usize);
            h.msg_controllen = control_buf.len();
            h
        };

        // Send with SCM_RIGHTS on a unix socket should succeed.
        let sent = task
            .do_sendmsg(sock1, &send_hdr, SendFlags::empty())
            .expect("sendmsg with SCM_RIGHTS should succeed");
        assert_eq!(sent, 1);

        // Receive via recvmsg — should get the fd back.
        let mut recv_data = [0u8; 1];
        let recv_iovec = [litebox_common_linux::IoVec {
            iov_base: MutPtr::from_usize(recv_data.as_mut_ptr() as usize),
            iov_len: recv_data.len(),
        }];
        let mut recv_control =
            vec![0u8; litebox_common_linux::cmsg_space(core::mem::size_of::<i32>())];
        let mut recv_hdr = {
            use zerocopy::FromZeros as _;
            let mut h = litebox_common_linux::UserMsgHdr::<crate::Platform>::new_zeroed();
            h.msg_iov = ConstPtr::from_usize(recv_iovec.as_ptr() as usize);
            h.msg_iovlen = recv_iovec.len();
            h.msg_control = ConstPtr::from_usize(recv_control.as_mut_ptr() as usize);
            h.msg_controllen = recv_control.len();
            h
        };
        let recv_hdr_ptr = MutPtr::from_usize((&raw mut recv_hdr) as usize);
        let received = task
            .sys_recvmsg(
                i32::try_from(sock2).unwrap(),
                recv_hdr_ptr,
                ReceiveFlags::empty(),
            )
            .expect("recvmsg should succeed");
        assert_eq!(received, 1);
        assert_eq!(recv_data[0], b'x');

        // Verify we got a control message back.
        let recv_controllen = { recv_hdr.msg_controllen };
        assert!(
            recv_controllen >= litebox_common_linux::cmsg_len(core::mem::size_of::<i32>()),
            "expected control data, got controllen={recv_controllen}"
        );

        // Parse the received cmsghdr.
        let recv_cmsg: litebox_common_linux::CmsgHdr =
            zerocopy::FromBytes::read_from_bytes(&recv_control[..hdr_size]).unwrap();
        assert_eq!(recv_cmsg.cmsg_level, 1); // SOL_SOCKET
        assert_eq!(recv_cmsg.cmsg_type, litebox_common_linux::SCM_RIGHTS);

        // Extract the received fd number.
        let mut fd_bytes = [0u8; 4];
        fd_bytes.copy_from_slice(&recv_control[aligned_hdr..aligned_hdr + 4]);
        let received_fd = i32::from_ne_bytes(fd_bytes);

        // The received fd should be a new fd (different from the one we sent).
        assert_ne!(received_fd, fd_to_pass);

        // Verify the received fd is alive.
        assert!(
            task.files
                .borrow()
                .raw_descriptor_store
                .read()
                .is_alive(usize::try_from(received_fd).unwrap()),
            "received fd should be alive"
        );

        #[allow(clippy::cast_sign_loss)]
        close_socket(&task, received_fd as u32);
        close_socket(&task, sock1);
        close_socket(&task, sock2);
    }

    fn unix_socket_recv_timeout(ty: SockType) {
        let task = init_platform(None);
        let (sock1, _sock2) = task
            .do_socketpair(AddressFamily::UNIX, ty, SockFlags::empty(), 0)
            .expect("socketpair failed");
        let timeout = Duration::from_millis(200);
        let tv = litebox_common_linux::TimeVal::from(timeout);
        let optval = ConstPtr::from_usize((&raw const tv).cast::<u8>() as usize);
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
        assert_eq!(err, Errno::ETIMEDOUT);
        // Allow a small tolerance (5ms) for timing imprecision
        let tolerance = Duration::from_millis(5);
        assert!(
            elapsed + tolerance >= timeout,
            "elapsed: {elapsed:?} < timeout: {timeout:?} (with {tolerance:?} tolerance)"
        );
    }
    #[test]
    #[ignore = "needs real broker; broker socketpair path lacks SO_RCVTIMEO enforcement"]
    fn test_unix_socket_recv_timeout() {
        unix_socket_recv_timeout(SockType::Stream);
        unix_socket_recv_timeout(SockType::Datagram);
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
        assert!(matches!(
            server_peer_result.unwrap_err(),
            Errno::ENOTCONN | Errno::EINVAL
        ));

        close_socket(&task, server_fd);
        close_socket(&task, client_fd);
        let _ = task.sys_unlinkat(-1, server_path, AtFlags::empty());
        let _ = task.sys_unlinkat(-1, client_path, AtFlags::empty());
    }

    #[test]
    #[ignore = "needs real broker; pair-id introspection is specific to legacy UnixSocket fds"]
    fn test_unix_socketpair_pair_id() {
        use crate::syscalls::unix::UnixSocket;

        let task = init_platform(None);
        let (fd1, fd2) = task
            .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::CLOEXEC, 0)
            .unwrap();

        let files = task.files.borrow();
        let rds = files.raw_descriptor_store.read();
        let typed1 = rds
            .fd_from_raw_integer::<crate::syscalls::unix::UnixSocketSubsystem<crate::DefaultFS>>(
                fd1 as usize,
            )
            .unwrap();
        let typed2 = rds
            .fd_from_raw_integer::<crate::syscalls::unix::UnixSocketSubsystem<crate::DefaultFS>>(
                fd2 as usize,
            )
            .unwrap();

        let dt = task.global.litebox.descriptor_table();
        let id1 = dt
            .with_entry(&typed1, |sock: &UnixSocket<crate::DefaultFS>| {
                sock.socket_pair_id()
            })
            .unwrap();
        let id2 = dt
            .with_entry(&typed2, |sock: &UnixSocket<crate::DefaultFS>| {
                sock.socket_pair_id()
            })
            .unwrap();

        assert_eq!(
            id1, id2,
            "both ends of a socketpair should have the same pair id"
        );
        assert!(
            id1.is_some(),
            "connected stream sockets should have a pair id"
        );
    }
}
