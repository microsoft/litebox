// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Socket-related syscalls, e.g., socket, bind, listen, etc.
//!
//! This module implements the parts of the socket calls that every address family shares, and
//! dispatches the rest to the family: [`super::inet`] for internet sockets and [`super::unix`]
//! for Unix domain sockets.

use core::{
    mem::{offset_of, size_of},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use litebox::{
    event::wait::WaitContext,
    fd::{EntryHandle, FdEnabledSubsystem},
    inet_socket::SOCKET_RECEIVE_OPERATION_SIZE,
    platform::page_mgmt::MemoryRegionPermissions,
    utils::TruncateExt as _,
};
use litebox_broker_protocol::{
    fs::FileOpenFlags,
    socket::{self, ShutdownMode},
};
use litebox_common_linux::{
    AddressFamily, FileDescriptorFlags, ReceiveFlags, SendFlags, ShutdownHow, SockFlags, SockType,
    SocketOption, SocketOptionName, UserMmsgHdr, UserMsgHdr, errno::Errno, signal::Signal,
};
use litebox_common_linux::{mm::VmemManager, vmem::PAGE_SIZE};
use litebox_platform::time::Instant as _;

use crate::syscalls::{
    file::{AnyTypedFd, FilesState},
    inet::{self, InetSocket, InetSocketSubsystem},
    unix::{self, UnixSocket, UnixSocketAddr, UnixSocketSubsystem},
};
use crate::{GlobalState, ShimPlatform, Task};
use crate::{UserPtr, UserPtrMut, syscalls::signal};

/// Linux's hard cap on the number of iovecs per `*msg`-style call, and on the
/// number of entries per `sendmmsg`. See `UIO_MAXIOV` in `<uapi/linux/uio.h>`.
const UIO_MAXIOV: usize = 1024;

enum ReceiveSocket<Platform: ShimPlatform> {
    Inet(EntryHandle<Platform, InetSocketSubsystem<Platform>>),
    Unix(EntryHandle<Platform, UnixSocketSubsystem<Platform>>),
}

/// How a receive call receives from its socket, which the socket's family decides.
pub(super) struct ReceivePlan {
    /// Whether the socket is a stream socket.
    pub(super) is_stream: bool,
    /// Whether the call receives until it fills its buffer (`MSG_WAITALL`).
    pub(super) wait_all: bool,
    /// The receive timeout that every receive of the call shares, or `None` for each receive to
    /// wait as long as the socket allows.
    pub(super) timeout: Option<Duration>,
    /// Whether the call copies the received data to the caller.
    pub(super) copies_data: bool,
}

impl<Platform: ShimPlatform> ReceiveSocket<Platform> {
    /// Plans a receive call with `flags`.
    fn plan(&self, flags: ReceiveFlags) -> Result<ReceivePlan, Errno> {
        match self {
            ReceiveSocket::Inet(handle) => handle.with_entry(|socket| socket.receive_plan(flags)),
            ReceiveSocket::Unix(handle) => Ok(handle.with_entry(UnixSocket::receive_plan)),
        }
    }

    /// Receives into `buf`, returning the length of the received data, which for a datagram
    /// socket may exceed `buf`.
    ///
    /// `has_prior_progress` tells whether the call already received data, which a failure
    /// then ends instead of being reported.
    ///
    /// A datagram socket stores its sender's address in `source_addr` if requested.
    fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        has_prior_progress: bool,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        let want_source = source_addr.is_some();
        let (size, addr) = match self {
            ReceiveSocket::Inet(handle) => {
                let mut addr = None;
                let size = handle.with_entry(|socket| {
                    socket.receive(
                        cx,
                        buf,
                        flags,
                        has_prior_progress,
                        want_source.then_some(&mut addr),
                    )
                })?;
                (size, addr.map(SocketAddress::Inet))
            }
            ReceiveSocket::Unix(handle) => {
                let mut addr = None;
                let size = handle.with_entry(|socket| {
                    socket.recvfrom(cx, buf, flags, want_source.then_some(&mut addr))
                })?;
                (size, addr.map(SocketAddress::Unix))
            }
        };
        if let (Some(source_addr), Some(addr)) = (source_addr, addr) {
            *source_addr = Some(addr);
        }
        Ok(size)
    }

    /// Peeks at the socket's data, returning whether it has any.
    fn probe(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: ReceiveFlags,
        has_prior_progress: bool,
    ) -> Result<bool, Errno> {
        let mut probe = [0];
        self.receive(
            cx,
            &mut probe,
            flags | ReceiveFlags::PEEK,
            has_prior_progress,
            None,
        )
        .map(|size| size != 0)
    }
}

impl<Platform: ShimPlatform> super::file::FilesState<Platform> {
    pub(super) fn socket_from_raw(&self, sockfd: i32) -> Result<AnyTypedFd<Platform>, Errno> {
        let fd = self.typed_fd(sockfd)?;
        match fd {
            AnyTypedFd::Inet(_) | AnyTypedFd::Unix(_) => Ok(fd),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    fn with_typed_socket<R>(
        &self,
        global: &GlobalState<Platform>,
        socket: &AnyTypedFd<Platform>,
        inet_op: impl FnOnce(&InetSocket<Platform>) -> Result<R, Errno>,
        unix_op: impl FnOnce(&UnixSocket<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        match socket {
            AnyTypedFd::Inet(fd) => global.with_inet_socket(fd, inet_op),
            AnyTypedFd::Unix(fd) => global.with_unix_socket(fd, unix_op),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    fn pin_receive_socket(
        &self,
        global: &GlobalState<Platform>,
        socket: &AnyTypedFd<Platform>,
    ) -> Result<ReceiveSocket<Platform>, Errno> {
        let descriptor_table = global.litebox.descriptor_table();
        match socket {
            AnyTypedFd::Inet(fd) => descriptor_table
                .entry_handle(fd)
                .map(ReceiveSocket::Inet)
                .ok_or(Errno::EBADF),
            AnyTypedFd::Unix(fd) => descriptor_table
                .entry_handle(fd)
                .map(ReceiveSocket::Unix)
                .ok_or(Errno::EBADF),
            _ => Err(Errno::ENOTSOCK),
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

/// Returns the status flags a new socket gets from the `SOCK_NONBLOCK` flag of `flags`.
pub(super) fn open_flags(flags: SockFlags) -> FileOpenFlags {
    if flags.contains(SockFlags::NONBLOCK) {
        FileOpenFlags::NONBLOCKING
    } else {
        FileOpenFlags::NONE
    }
}

pub(super) fn shutdown_mode(how: ShutdownHow) -> ShutdownMode {
    match how {
        ShutdownHow::Read => ShutdownMode::Read,
        ShutdownHow::Write => ShutdownMode::Write,
        ShutdownHow::Both => ShutdownMode::Both,
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Common implementation of `setsockopt` for the socket-level options every socket stores:
    /// RCVTIMEO, SNDTIMEO, LINGER, REUSEADDR, KEEPALIVE, and BROADCAST.
    ///
    /// Reads the value of `optname` from user memory and passes it to `set_option`, or fails
    /// with `ENOPROTOOPT` for any other option.
    pub(super) fn setsockopt_common(
        &self,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
        optlen: usize,
        set_option: impl FnOnce(socket::SocketOptionValue) -> Result<(), Errno>,
    ) -> Result<(), Errno> {
        let SocketOptionName::Socket(sopt) = optname else {
            return Err(Errno::ENOPROTOOPT);
        };
        let value = match sopt {
            SocketOption::RCVTIMEO | SocketOption::SNDTIMEO => {
                let timeval = super::read_from_user::<litebox_common_linux::TimeVal, Platform>(
                    optval, optlen,
                )?;
                let duration = core::time::Duration::try_from(timeval)?;
                // A zero timeout waits indefinitely.
                let timeout = (!duration.is_zero()).then_some(duration);
                if matches!(sopt, SocketOption::RCVTIMEO) {
                    socket::SocketOptionValue::ReceiveTimeout(timeout)
                } else {
                    socket::SocketOptionValue::SendTimeout(timeout)
                }
            }
            SocketOption::LINGER => {
                let linger: litebox_common_linux::Linger =
                    super::read_from_user::<_, Platform>(optval, optlen)?;
                socket::SocketOptionValue::Linger(
                    (linger.onoff != 0)
                        .then(|| core::time::Duration::from_secs(u64::from(linger.linger))),
                )
            }
            SocketOption::REUSEADDR | SocketOption::BROADCAST | SocketOption::KEEPALIVE => {
                let enabled = super::read_from_user::<u32, Platform>(optval, optlen)? != 0;
                match sopt {
                    SocketOption::REUSEADDR => socket::SocketOptionValue::ReuseAddress(enabled),
                    SocketOption::BROADCAST => socket::SocketOptionValue::Broadcast(enabled),
                    _ => socket::SocketOptionValue::KeepAlive(enabled),
                }
            }
            _ => return Err(Errno::ENOPROTOOPT),
        };
        set_option(value)
    }

    /// Common implementation of `getsockopt` for the socket-level options every socket stores:
    /// RCVTIMEO, SNDTIMEO, LINGER, REUSEADDR, KEEPALIVE, and BROADCAST.
    ///
    /// Writes the value `get_option` returns for `optname` to user memory, returning its length,
    /// or fails with `ENOPROTOOPT` for any other option.
    pub(super) fn getsockopt_common(
        &self,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
        len: u32,
        get_option: impl FnOnce(socket::SocketOptionName) -> Result<socket::SocketOptionValue, Errno>,
    ) -> Result<usize, Errno> {
        let name = match optname {
            SocketOptionName::Socket(SocketOption::RCVTIMEO) => {
                socket::SocketOptionName::ReceiveTimeout
            }
            SocketOptionName::Socket(SocketOption::SNDTIMEO) => {
                socket::SocketOptionName::SendTimeout
            }
            SocketOptionName::Socket(SocketOption::LINGER) => socket::SocketOptionName::Linger,
            SocketOptionName::Socket(SocketOption::REUSEADDR) => {
                socket::SocketOptionName::ReuseAddress
            }
            SocketOptionName::Socket(SocketOption::KEEPALIVE) => {
                socket::SocketOptionName::KeepAlive
            }
            SocketOptionName::Socket(SocketOption::BROADCAST) => {
                socket::SocketOptionName::Broadcast
            }
            _ => return Err(Errno::ENOPROTOOPT),
        };
        match get_option(name)? {
            socket::SocketOptionValue::ReceiveTimeout(timeout)
            | socket::SocketOptionValue::SendTimeout(timeout)
            | socket::SocketOptionValue::Linger(timeout) => {
                let tv = timeout.map_or_else(
                    litebox_common_linux::TimeVal::default,
                    litebox_common_linux::TimeVal::from,
                );
                super::write_to_user::<_, Platform>(tv, optval, len)
            }
            socket::SocketOptionValue::ReuseAddress(enabled)
            | socket::SocketOptionValue::KeepAlive(enabled)
            | socket::SocketOptionValue::Broadcast(enabled) => {
                super::write_to_user::<_, Platform>(u32::from(enabled), optval, len)
            }
            value @ socket::SocketOptionValue::NoDelay(_) => {
                unreachable!("{value:?} is not a socket-level option")
            }
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

impl<Platform: ShimPlatform> Task<Platform> {
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
                let socket = InetSocket::new(&self.global.litebox, ty, protocol, flags)?;
                self.insert_socket::<InetSocketSubsystem<Platform>>(&files, socket, flags)?
            }
            AddressFamily::UNIX => {
                let socket = UnixSocket::new(&self.global.litebox, ty, protocol, flags)?;
                self.insert_socket::<UnixSocketSubsystem<Platform>>(&files, socket, flags)?
            }
            AddressFamily::INET6 | AddressFamily::NETLINK => return Err(Errno::EAFNOSUPPORT),
            _ => unimplemented!(),
        };
        Ok(u32::try_from(file).unwrap())
    }

    /// Publishes `socket` as a new file descriptor, closing it on failure.
    ///
    /// `SOCK_CLOEXEC` in `flags` sets the descriptor's close-on-exec flag.
    fn insert_socket<S: FdEnabledSubsystem>(
        &self,
        files: &FilesState<Platform>,
        socket: S::Entry,
        flags: SockFlags,
    ) -> Result<usize, Errno> {
        let typed = {
            let mut dt = self.global.litebox.descriptor_table_mut();
            let typed = dt.insert::<S>(socket);
            if flags.contains(SockFlags::CLOEXEC) {
                let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
                assert!(old.is_none());
            }
            typed
        };
        files.insert_raw_fd(typed).map_err(|typed| {
            self.remove_and_drop_descriptor(&typed);
            Errno::EMFILE
        })
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

    pub(super) fn do_socketpair(
        &self,
        domain: AddressFamily,
        ty: SockType,
        flags: SockFlags,
        protocol: u8,
    ) -> Result<(u32, u32), Errno> {
        let (desc1, desc2) = match domain {
            AddressFamily::UNIX => {
                let (sock1, sock2) =
                    UnixSocket::new_connected_pair(&self.global.litebox, ty, protocol, flags)?;
                let files = self.files.borrow();
                let mut dt = self.global.litebox.descriptor_table_mut();
                let typed1 = dt.insert::<UnixSocketSubsystem<Platform>>(sock1);
                let typed2 = dt.insert::<UnixSocketSubsystem<Platform>>(sock2);
                if flags.contains(SockFlags::CLOEXEC) {
                    let old = dt.set_fd_metadata(&typed1, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                    let old = dt.set_fd_metadata(&typed2, FileDescriptorFlags::FD_CLOEXEC);
                    assert!(old.is_none());
                }
                drop(dt);
                // Both inserts and the rollback of the first one must happen under a single
                // acquisition of the raw descriptor store lock: otherwise a concurrent `close`
                // could free the first socket's slot and another thread could take it over,
                // making the rollback remove an unrelated file descriptor.
                let mut rds = files.raw_descriptor_store.write();
                let raw_fd1 = match files.insert_raw_fd_locked(&mut rds, typed1) {
                    Ok(raw_fd) => raw_fd,
                    Err(typed1) => {
                        drop(rds);
                        self.remove_and_drop_descriptor(&typed1);
                        self.remove_and_drop_descriptor(&typed2);
                        return Err(Errno::EMFILE);
                    }
                };
                let raw_fd2 = match files.insert_raw_fd_locked(&mut rds, typed2) {
                    Ok(raw_fd) => raw_fd,
                    Err(typed2) => {
                        let typed1 = rds
                            .fd_consume_raw_integer::<UnixSocketSubsystem<Platform>>(raw_fd1)
                            .unwrap();
                        drop(rds);
                        self.remove_and_drop_descriptor(&typed1);
                        self.remove_and_drop_descriptor(&typed2);
                        return Err(Errno::EMFILE);
                    }
                };
                drop(rds);
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
        AddressFamily::INET => Ok(SocketAddress::Inet(inet::read_sockaddr::<Platform>(
            sockaddr, addrlen,
        )?)),
        AddressFamily::UNIX => Ok(SocketAddress::Unix(unix::read_sockaddr::<Platform>(
            sockaddr, addrlen,
        )?)),
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
    let capacity = addrlen_val as usize;
    let len: u32 = match sock_addr {
        SocketAddress::Inet(addr_v) => inet::write_sockaddr::<Platform>(addr_v, addr, capacity)?,
        SocketAddress::Unix(addr_v) => unix::write_sockaddr::<Platform>(addr_v, addr, capacity)?,
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
    page_manager: &VmemManager<Platform, PAGE_SIZE>,
    ptr: UserPtrMut<u8>,
    offset: usize,
    len: usize,
) -> Result<usize, Errno> {
    let start = ptr.as_usize().checked_add(offset).ok_or(Errno::EFAULT)?;
    let end = start.checked_add(len).ok_or(Errno::EFAULT)?;
    Ok(page_manager.range_prefix_with_permissions(start..end, MemoryRegionPermissions::WRITE))
}

fn iov_write_prefix<Platform: ShimPlatform>(
    page_manager: &VmemManager<Platform, PAGE_SIZE>,
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

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `accept`
    pub(crate) fn sys_accept(
        &self,
        sockfd: i32,
        addr: Option<UserPtrMut<u8>>,
        addrlen: Option<UserPtrMut<u32>>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        let mut remote_addr = addr.is_some().then(SocketAddress::default);
        let fd = self.do_accept(&socket, remote_addr.as_mut(), flags)?;
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
    pub(super) fn do_accept(
        &self,
        socket: &AnyTypedFd<Platform>,
        peer: Option<&mut SocketAddress>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let files = self.files.borrow();
        let want_peer = peer.is_some();
        let (file, peer_addr) = files.with_typed_socket(
            &self.global,
            socket,
            |socket| {
                let mut socket_addr =
                    want_peer.then(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
                let accepted = socket.accept(&self.wait_cx(), flags, socket_addr.as_mut())?;
                let raw_fd =
                    self.insert_socket::<InetSocketSubsystem<Platform>>(&files, accepted, flags)?;
                Ok((raw_fd, socket_addr.map(SocketAddress::Inet)))
            },
            |socket| {
                let mut socket_addr = want_peer.then_some(UnixSocketAddr::Unnamed);
                let accepted = socket.accept(&self.wait_cx(), flags, socket_addr.as_mut())?;
                let raw_fd =
                    self.insert_socket::<UnixSocketSubsystem<Platform>>(&files, accepted, flags)?;
                Ok((raw_fd, socket_addr.map(SocketAddress::Unix)))
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
        let socket = self.files.borrow().socket_from_raw(fd)?;
        let sockaddr = read_sockaddr_from_user::<Platform>(sockaddr, addrlen)?;
        self.do_connect(&socket, sockaddr)
    }
    pub(super) fn do_connect(
        &self,
        socket: &AnyTypedFd<Platform>,
        sockaddr: SocketAddress,
    ) -> Result<(), Errno> {
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| {
                let addr = sockaddr.clone().inet().ok_or(Errno::EAFNOSUPPORT)?;
                socket.connect(&self.wait_cx(), addr)
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
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        let sockaddr = read_sockaddr_from_user::<Platform>(sockaddr, addrlen)?;
        self.do_bind(&socket, sockaddr)
    }
    pub(super) fn do_bind(
        &self,
        socket: &AnyTypedFd<Platform>,
        sockaddr: SocketAddress,
    ) -> Result<(), Errno> {
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| {
                let addr = sockaddr.clone().inet().ok_or(Errno::EAFNOSUPPORT)?;
                socket.bind(addr)
            },
            |file| {
                let addr = sockaddr.clone().unix().ok_or(Errno::EAFNOSUPPORT)?;
                file.bind(self, addr)
            },
        )
    }

    /// Handle syscall `listen`
    pub(crate) fn sys_listen(&self, sockfd: i32, backlog: u16) -> Result<(), Errno> {
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        self.do_listen(&socket, backlog)
    }
    pub(super) fn do_listen(
        &self,
        socket: &AnyTypedFd<Platform>,
        backlog: u16,
    ) -> Result<(), Errno> {
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| socket.listen(backlog),
            |file| file.listen(backlog),
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
        let socket = self.files.borrow().socket_from_raw(fd)?;
        let sockaddr = addr
            .map(|addr| read_sockaddr_from_user::<Platform>(addr, addrlen as usize))
            .transpose()?;
        let buf = buf.to_owned_slice::<Platform>(len).ok_or(Errno::EFAULT)?;
        self.do_sendto(&socket, &buf, flags, sockaddr)
    }
    pub(super) fn do_sendto(
        &self,
        socket: &AnyTypedFd<Platform>,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddress>,
    ) -> Result<usize, Errno> {
        let is_datagram = core::cell::Cell::new(false);
        let res = self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| {
                is_datagram.set(!socket.is_stream());
                let sockaddr = sockaddr
                    .clone()
                    .map(|addr| addr.inet().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                socket.sendto(&self.wait_cx(), buf, flags, sockaddr)
            },
            |file| {
                let addr = sockaddr
                    .clone()
                    .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                is_datagram.set(!file.is_stream());
                file.sendto(self, buf, flags, addr)
            },
        );
        // Like Linux, datagram sockets report EPIPE without raising SIGPIPE.
        if let Err(Errno::EPIPE) = res
            && !flags.contains(SendFlags::NOSIGNAL)
            && !is_datagram.get()
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
        let socket = self.files.borrow().socket_from_raw(fd)?;
        let msg = msg.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        self.do_sendmsg(&socket, &msg, flags)
    }

    pub(super) fn do_sendmsg(
        &self,
        socket: &AnyTypedFd<Platform>,
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
        let is_datagram = core::cell::Cell::new(false);
        let res = self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| {
                is_datagram.set(!socket.is_stream());
                let sock_addr = sock_addr
                    .clone()
                    .map(|addr| addr.inet().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                let data = copy_iovs_to_vec::<Platform>(iovs.as_deref().unwrap_or_default())?;
                socket.sendto(&self.wait_cx(), &data, flags, sock_addr)
            },
            |file| {
                let unix_addr = sock_addr
                    .clone()
                    .map(|addr| addr.unix().ok_or(Errno::EAFNOSUPPORT))
                    .transpose()?;
                let data = copy_iovs_to_vec::<Platform>(iovs.as_deref().unwrap_or_default())?;
                is_datagram.set(!file.is_stream());
                file.sendto(self, &data, flags, unix_addr)
            },
        );
        // Like Linux, datagram sockets report EPIPE without raising SIGPIPE.
        if let Err(Errno::EPIPE) = res
            && !flags.contains(SendFlags::NOSIGNAL)
            && !is_datagram.get()
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
        let vlen = (vlen as usize).min(UIO_MAXIOV);

        // Linux looks up the fd before touching vlen/msgvec, so a bogus fd
        // takes priority over a bogus msgvec pointer or vlen == 0.
        let socket = self.files.borrow().socket_from_raw(fd)?;

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
            let n = match self.do_sendmsg(&socket, &inner, flags) {
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
        let typed_socket = self.files.borrow().socket_from_raw(fd)?;
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, &typed_socket)?;
        let plan = socket.plan(flags)?;
        let cx = self.wait_cx().with_timeout(plan.timeout);
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
            let write_prefix = (plan.is_stream && plan.copies_data && requested_chunk_len != 0)
                .then(|| user_write_prefix(&self.global.mm, buf, received, requested_chunk_len));
            let needs_probe = write_prefix.as_ref().is_some_and(
                |prefix| !matches!(prefix, Ok(prefix) if *prefix == requested_chunk_len),
            );
            let data_available = if needs_probe {
                socket.probe(&cx, flags, received != 0)?
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
            let size = socket.receive(
                &cx,
                &mut buffer[..chunk_len],
                flags,
                received != 0,
                if addr.is_some() {
                    Some(&mut source_addr)
                } else {
                    None
                },
            )?;
            let copied = size.min(chunk_len);
            if plan.copies_data
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
            let reported = if plan.wait_all { received } else { size };
            if !plan.wait_all || copied < chunk_len || received == len {
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

    /// Receive data from a socket.
    ///
    /// `source_addr` can be provided to receive the source address if available.
    ///
    /// On success, returns the number of bytes received. Note that for datagram sockets,
    /// this may be larger than the provided buffer length as the excessive data will be truncated.
    #[cfg(test)]
    pub(super) fn do_recvfrom(
        &self,
        socket: &AnyTypedFd<Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, socket)?;
        socket.receive(&self.wait_cx(), buf, flags, false, source_addr)
    }

    /// Handle syscall `recvmsg`
    pub(crate) fn sys_recvmsg(
        &self,
        fd: i32,
        msg_ptr: UserPtrMut<litebox_common_linux::UserMsgHdr>,
        flags: ReceiveFlags,
    ) -> Result<usize, Errno> {
        let supported_flags = ReceiveFlags::DONTWAIT
            | ReceiveFlags::PEEK
            | ReceiveFlags::TRUNC
            | ReceiveFlags::WAITALL;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvmsg flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }

        let typed_socket = self.files.borrow().socket_from_raw(fd)?;
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, &typed_socket)?;
        self.do_recvmsg(&socket, msg_ptr, flags)
    }

    fn do_recvmsg(
        &self,
        socket: &ReceiveSocket<Platform>,
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
        let plan = socket.plan(flags)?;
        let cx = self.wait_cx().with_timeout(plan.timeout);

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
            let write_prefix = (plan.is_stream && plan.copies_data && requested_chunk_len != 0)
                .then(|| {
                    iov_write_prefix(&self.global.mm, &iovs, total_received, requested_chunk_len)
                });
            let needs_probe = write_prefix.as_ref().is_some_and(
                |prefix| !matches!(prefix, Ok(prefix) if *prefix == requested_chunk_len),
            );
            let data_available = if needs_probe {
                socket.probe(&cx, flags, total_received != 0)?
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
            let size = socket.receive(
                &cx,
                &mut buffer[..chunk_len],
                flags,
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
            if plan.copies_data {
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
            let reported = if plan.wait_all { total_received } else { size };
            if !plan.wait_all || copied < chunk_len || total_received == total_iov_capacity {
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

        let vlen = vlen as usize;

        // Linux looks up the fd before touching vlen/msgvec, so a bogus fd
        // takes priority over a bogus msgvec pointer or vlen == 0.
        let typed_socket = self.files.borrow().socket_from_raw(fd)?;
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, &typed_socket)?;

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
            let n = match self.do_recvmsg(&socket, inner_ptr, iter_flags) {
                Ok(n) => n,
                Err(e) => {
                    if received > 0 {
                        async_error_to_restore = Some(e);
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

        // Stash the suppressed socket error back onto the socket; Unix sockets don't track
        // asynchronous errors.
        if let (Some(async_error), ReceiveSocket::Inet(handle)) = (async_error_to_restore, &socket)
        {
            handle.with_entry(|socket| socket.set_async_error(async_error));
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
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            log_unsupported!("setsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        })?;
        self.do_setsockopt(&socket, optname, optval, optlen)
    }
    pub(super) fn do_setsockopt(
        &self,
        socket: &AnyTypedFd<Platform>,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| socket.setsockopt(&self.global, optname, optval, optlen),
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
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            log_unsupported!("setsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        })?;
        let len = optlen.read_at_offset::<Platform>(0).ok_or(Errno::EFAULT)?;
        if len > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        let new_len = self.do_getsockopt(&socket, optname, optval, len)?;
        optlen
            .write_at_offset::<Platform>(0, new_len.trunc())
            .ok_or(Errno::EFAULT)?;
        Ok(())
    }
    /// Actual implementation of `getsockopt`
    ///
    /// Returns the length of the option value written to `optval` on success.
    pub(super) fn do_getsockopt(
        &self,
        socket: &AnyTypedFd<Platform>,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| socket.getsockopt(&self.global, optname, optval, len),
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
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        let sockaddr = self.do_getsockname(&socket)?;
        write_sockaddr_to_user::<Platform>(sockaddr, addr, addrlen)
    }
    pub(super) fn do_getsockname(
        &self,
        socket: &AnyTypedFd<Platform>,
    ) -> Result<SocketAddress, Errno> {
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| Ok(SocketAddress::Inet(socket.get_local_addr())),
            |unix| unix.get_local_addr().map(SocketAddress::Unix),
        )
    }

    /// Handle syscall `getpeername`
    pub(crate) fn sys_getpeername(
        &self,
        sockfd: i32,
        addr: UserPtrMut<u8>,
        addrlen: UserPtrMut<u32>,
    ) -> Result<(), Errno> {
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        let sockaddr = self.do_getpeername(&socket)?;
        write_sockaddr_to_user::<Platform>(sockaddr, addr, addrlen)
    }
    pub(super) fn do_getpeername(
        &self,
        socket: &AnyTypedFd<Platform>,
    ) -> Result<SocketAddress, Errno> {
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| socket.get_peer_addr().map(SocketAddress::Inet),
            |file| file.get_peer_addr().map(SocketAddress::Unix),
        )
    }

    /// Handle syscall `shutdown`
    pub(crate) fn sys_shutdown(&self, sockfd: i32, how: i32) -> Result<(), Errno> {
        let socket = self.files.borrow().socket_from_raw(sockfd)?;
        self.do_shutdown(&socket, how)
    }
    fn do_shutdown(&self, socket: &AnyTypedFd<Platform>, how: i32) -> Result<(), Errno> {
        // Linux validates the fd (EBADF, ENOTSOCK) before `how` (EINVAL),
        // so resolve the socket first and validate `how`
        // only inside the matching branch.
        self.files.borrow().with_typed_socket(
            &self.global,
            socket,
            |socket| {
                let how = ShutdownHow::try_from(how).map_err(|_| Errno::EINVAL)?;
                socket.shutdown(how)
            },
            |file| {
                let how = ShutdownHow::try_from(how).map_err(|_| Errno::EINVAL)?;
                file.shutdown(how)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::{AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType};

    use crate::syscalls::tests::init_platform;

    type TestTask = crate::Task<crate::syscalls::tests::TestPlatform>;

    // Compile-time layout check: UserMsgHdr must match Linux's struct user_msghdr.
    #[cfg(target_os = "linux")]
    const _USER_MSG_HDR_SIZE: () = assert!(
        core::mem::size_of::<litebox_common_linux::UserMsgHdr>()
            == core::mem::size_of::<libc::msghdr>()
    );

    fn close_socket(task: &TestTask, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
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

    #[test]
    fn pinned_receive_does_not_follow_dup2_replacement() {
        let task = init_platform();
        let (old_sender, old_receiver) = task
            .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0)
            .unwrap();
        let (new_sender, new_receiver) = task
            .do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0)
            .unwrap();
        let old_sender_typed = typed_socket(&task, old_sender);
        let old_receiver_typed = typed_socket(&task, old_receiver);
        let new_sender_typed = typed_socket(&task, new_sender);
        task.do_sendto(&old_sender_typed, b"old", SendFlags::empty(), None)
            .unwrap();
        task.do_sendto(&new_sender_typed, b"new", SendFlags::empty(), None)
            .unwrap();

        let socket = task
            .files
            .borrow()
            .pin_receive_socket(&task.global, &old_receiver_typed)
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
        let received = socket
            .receive(
                &task.wait_cx(),
                &mut old,
                ReceiveFlags::empty(),
                false,
                None,
            )
            .unwrap();
        assert_eq!(received, old.len());
        assert_eq!(&old, b"old");

        let mut new = [0; 3];
        let replacement = typed_socket(&task, old_receiver);
        let received = task
            .do_recvfrom(&replacement, &mut new, ReceiveFlags::empty(), None)
            .unwrap();
        assert_eq!(received, new.len());
        assert_eq!(&new, b"new");

        drop(socket);
        close_socket(&task, old_sender);
        close_socket(&task, old_receiver);
        close_socket(&task, new_sender);
        close_socket(&task, new_receiver);
    }
}
