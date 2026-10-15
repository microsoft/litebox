// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Socket-related syscalls, e.g., socket, bind, listen, etc.

use core::{
    mem::{offset_of, size_of},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use alloc::string::String;
use alloc::sync::Arc;
use litebox::{
    fd::{EntryHandle, FdEnabledSubsystem},
    inet_socket::SOCKET_RECEIVE_OPERATION_SIZE,
    platform::page_mgmt::MemoryRegionPermissions,
    utils::TruncateExt as _,
};
use litebox_broker_protocol::{
    fs::FileOpenFlags,
    socket::{self, ShutdownMode, SocketType},
};
use litebox_common_linux::{
    AddressFamily, FileDescriptorFlags, IPProtocol, ReceiveFlags, SendFlags, ShutdownHow,
    SockFlags, SockType, SocketOption, SocketOptionName, UnixProtocol, UserMmsgHdr, UserMsgHdr,
    errno::Errno, signal::Signal,
};
use litebox_common_linux::{mm::VmemManager, vmem::PAGE_SIZE};
use litebox_platform::time::Instant as _;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::{
    file::{AnyTypedFd, FilesState},
    inet::{InetSocket, InetSocketSubsystem, ReceiveContext},
    unix::{CSockUnixAddr, UnixSocket, UnixSocketAddr, UnixSocketSubsystem},
};
use crate::wait::wait_errno;
use crate::{GlobalState, ShimPlatform, Task};
use crate::{UserPtr, UserPtrMut, syscalls::signal};

/// Linux's hard cap on the number of iovecs per `*msg`-style call, and on the
/// number of entries per `sendmmsg`. See `UIO_MAXIOV` in `<uapi/linux/uio.h>`.
const UIO_MAXIOV: usize = 1024;

enum ReceiveSocket<Platform: ShimPlatform> {
    Inet(EntryHandle<Platform, InetSocketSubsystem<Platform>>),
    Unix(EntryHandle<Platform, UnixSocketSubsystem<Platform>>),
}

impl<Platform: ShimPlatform> super::file::FilesState<Platform> {
    fn socket_from_raw(&self, sockfd: i32) -> Result<AnyTypedFd<Platform>, Errno> {
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
                let socket = InetSocket::new(&self.global.litebox, socket_type, flags)?;
                self.insert_socket::<InetSocketSubsystem<Platform>>(&files, socket, flags)?
            }
            AddressFamily::UNIX => {
                let _ = UnixProtocol::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
                let socket = UnixSocket::new(&self.global.litebox, ty, flags)?;
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
                    UnixSocket::new_connected_pair(&self.global.litebox, ty, flags)?;
                let files = self.files.borrow();
                let mut dt = self.global.litebox.descriptor_table_mut();
                let typed1 =
                    dt.insert::<crate::syscalls::unix::UnixSocketSubsystem<Platform>>(sock1);
                let typed2 =
                    dt.insert::<crate::syscalls::unix::UnixSocketSubsystem<Platform>>(sock2);
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
                        let typed1 = rds.fd_consume_raw_integer::<crate::syscalls::unix::UnixSocketSubsystem<Platform>>(raw_fd1).unwrap();
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
            if addrlen > size_of::<CSockUnixAddr>() {
                return Err(Errno::EINVAL);
            }
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
            // Like Linux, accept a path without a NUL terminator (e.g., `addrlen = SUN_LEN(addr)`).
            let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            Ok(SocketAddress::Unix(UnixSocketAddr::Path(
                String::from_utf8_lossy(&path[..end]).into_owned(),
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
            // Like Linux, copy the full address truncated to the caller's buffer, which may be
            // too small even for the family.
            let mut bytes = alloc::vec::Vec::new();
            bytes.extend_from_slice(&(AddressFamily::UNIX as u16).to_ne_bytes());
            match v {
                UnixSocketAddr::Unnamed => {}
                UnixSocketAddr::Abstract(name) => {
                    bytes.push(0);
                    bytes.extend_from_slice(&name);
                }
                UnixSocketAddr::Path(path) => {
                    bytes.extend_from_slice(path.as_bytes());
                    bytes.push(0);
                }
            }
            let copied = bytes.len().min(addrlen_val as usize);
            if copied != 0 {
                addr.write_slice_at_offset::<Platform>(0, &bytes[..copied])
                    .ok_or(Errno::EFAULT)?;
            }
            bytes.len()
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
    fn do_accept(
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
    fn do_connect(
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
    fn do_bind(&self, socket: &AnyTypedFd<Platform>, sockaddr: SocketAddress) -> Result<(), Errno> {
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
    fn do_listen(&self, socket: &AnyTypedFd<Platform>, backlog: u16) -> Result<(), Errno> {
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
    fn do_sendto(
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

    fn do_sendmsg(
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
                .then(|| user_write_prefix(&self.global.mm, buf, received, requested_chunk_len));
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
        socket: &ReceiveSocket<Platform>,
        flags: ReceiveFlags,
    ) -> Result<(bool, bool, Option<Platform::Instant>), Errno> {
        match socket {
            ReceiveSocket::Inet(handle) => handle.with_entry(|socket| {
                let is_stream = socket.is_stream();
                let chunk_waitall = flags.contains(ReceiveFlags::WAITALL)
                    && !flags.contains(ReceiveFlags::PEEK)
                    && is_stream
                    && !flags.contains(ReceiveFlags::DONTWAIT)
                    && !socket.is_nonblocking()?;
                // The chunks of a `MSG_WAITALL` receive share one receive timeout.
                let deadline = if chunk_waitall {
                    socket
                        .receive_timeout()?
                        .map(|timeout| {
                            self.global
                                .platform
                                .now()
                                .checked_add(timeout)
                                .ok_or(Errno::EINVAL)
                        })
                        .transpose()?
                } else {
                    None
                };
                Ok((chunk_waitall, is_stream, deadline))
            }),
            // No deadline: `litebox::unix_socket::UnixSocket` bounds each
            // blocking receive by the socket's stored receive timeout itself.
            ReceiveSocket::Unix(handle) => {
                Ok((false, handle.with_entry(UnixSocket::is_stream), None))
            }
        }
    }

    fn receive_copies_data(socket: &ReceiveSocket<Platform>, flags: ReceiveFlags) -> bool {
        if !flags.contains(ReceiveFlags::TRUNC) {
            return true;
        }
        match socket {
            ReceiveSocket::Inet(handle) => !handle.with_entry(InetSocket::is_stream),
            ReceiveSocket::Unix(_) => true,
        }
    }

    fn probe_receive(
        &self,
        socket: &ReceiveSocket<Platform>,
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
        socket: &AnyTypedFd<Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        let socket = self
            .files
            .borrow()
            .pin_receive_socket(&self.global, socket)?;
        self.do_recvfrom_with_copy(&socket, buf, flags, None, false, source_addr)
            .map(|(size, _)| size)
    }

    fn do_recvfrom_with_copy(
        &self,
        socket: &ReceiveSocket<Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        deadline: Option<Platform::Instant>,
        outer_partial: bool,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<(usize, bool), Errno> {
        let want_source = source_addr.is_some();
        let (size, addr, copy_received) = match socket {
            ReceiveSocket::Inet(handle) => handle.with_entry(|socket| {
                let mut addr = None;
                let timeout = deadline.map(|deadline| {
                    deadline
                        .checked_duration_since(&self.global.platform.now())
                        .unwrap_or(core::time::Duration::ZERO)
                });
                let size = socket.receive(
                    &self.wait_cx(),
                    buf,
                    flags,
                    ReceiveContext::new(timeout, outer_partial),
                    if want_source { Some(&mut addr) } else { None },
                )?;
                let src_addr = addr.map(SocketAddress::Inet);
                let copy_received = !(flags.contains(ReceiveFlags::TRUNC) && socket.is_stream());
                Ok::<_, Errno>((size, src_addr, copy_received))
            })?,
            ReceiveSocket::Unix(handle) => handle.with_entry(|entry| {
                let mut addr = None;
                let size = entry.recvfrom(
                    &self.wait_cx(),
                    buf,
                    flags,
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
                    iov_write_prefix(&self.global.mm, &iovs, total_received, requested_chunk_len)
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

        let recvmmsg_lock = match &socket {
            ReceiveSocket::Inet(handle) if vlen > 1 => {
                Some(handle.with_entry(|socket| Arc::clone(socket.recvmmsg_lock())))
            }
            _ => None,
        };
        let _recvmmsg = match (&recvmmsg_lock, &socket) {
            (Some(lock), ReceiveSocket::Inet(handle)) => Some(match lock.try_lock() {
                Some(guard) => guard,
                None if flags.contains(ReceiveFlags::DONTWAIT)
                    || handle.with_entry(InetSocket::is_nonblocking)? =>
                {
                    return Err(Errno::EAGAIN);
                }
                None => lock
                    .lock_interruptibly(&self.wait_cx().with_deadline(deadline))
                    .map_err(|error| {
                        let timeout = timeout_duration.or_else(|| {
                            handle
                                .with_entry(InetSocket::receive_timeout)
                                .ok()
                                .flatten()
                        });
                        wait_errno(timeout, error)
                    })?,
            }),
            _ => None,
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
        if let (Some(async_error), ReceiveSocket::Inet(handle)) = (async_error_to_restore, &socket)
        {
            handle.with_entry(|socket| socket.inet_socket().set_async_error(async_error));
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
    fn do_setsockopt(
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
    fn do_getsockopt(
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
    fn do_getsockname(&self, socket: &AnyTypedFd<Platform>) -> Result<SocketAddress, Errno> {
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
    fn do_getpeername(&self, socket: &AnyTypedFd<Platform>) -> Result<SocketAddress, Errno> {
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

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    type TestTask = crate::Task<crate::syscalls::tests::TestPlatform>;

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

        let mut remote_addr = super::SocketAddress::default();
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
        let super::SocketAddress::Inet(SocketAddr::V4(remote_v4)) = remote_addr.clone() else {
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

#[cfg(test)]
mod unix_tests {
    use core::time::Duration;

    type TestTask = crate::Task<crate::syscalls::tests::TestPlatform>;

    use alloc::{string::ToString, vec::Vec};
    use litebox::event::Events;
    use litebox_common_linux::{
        AddressFamily, AtFlags, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption,
        SocketOptionName, TimeParam, errno::Errno,
    };

    use crate::{
        UserPtr, UserPtrMut,
        syscalls::{
            net::{SocketAddress, read_sockaddr_from_user},
            tests::init_platform,
            unix::UnixSocketAddr,
        },
    };

    extern crate std;

    fn create_unix_socket(task: &TestTask, ty: SockType, flags: SockFlags) -> u32 {
        task.do_socket(AddressFamily::UNIX, ty, flags, 0).unwrap()
    }

    fn create_unix_server_socket(
        task: &TestTask,
        addr: UnixSocketAddr,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let raw_server_fd = create_unix_socket(task, SockType::Stream, flags);
        let server_fd = typed_socket(task, raw_server_fd);
        if let Err(error) = task.do_bind(&server_fd, SocketAddress::Unix(addr)) {
            close_socket(task, raw_server_fd);
            return Err(error);
        }
        if let Err(error) = task.do_listen(&server_fd, 1) {
            close_socket(task, raw_server_fd);
            return Err(error);
        }
        Ok(raw_server_fd)
    }

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
            let raw_server_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let raw_client_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let server_fd = typed_socket(&task, raw_server_fd);
            let client_fd = typed_socket(&task, raw_client_fd);
            let server_addr =
                SocketAddress::Unix(UnixSocketAddr::Abstract(b"datagram-server".to_vec()));
            let client_addr =
                SocketAddress::Unix(UnixSocketAddr::Abstract(b"datagram-client".to_vec()));
            task.do_bind(&server_fd, server_addr.clone())
                .expect("server bind failed");
            task.do_bind(&client_fd, client_addr.clone())
                .expect("client bind failed");

            // send message from server to client
            let msg1 = "Hello from server";
            let n = task
                .do_sendto(
                    &server_fd,
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
                    &client_fd,
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
                    &client_fd,
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
                    &server_fd,
                    &mut buf,
                    ReceiveFlags::empty(),
                    Some(&mut source),
                )
                .expect("recvfrom failed");
            assert_eq!(n, msg2.len());
            assert_eq!(&buf[..n], b"Hello from client");
            assert_eq!(source, Some(client_addr));

            close_socket(&task, raw_server_fd);
            close_socket(&task, raw_client_fd);
        }
    }

    #[test]
    fn test_unix_stream_socket() {
        let task = init_platform();

        for _ in 0..10 {
            let addr = UnixSocketAddr::Abstract(b"stream-socket".to_vec());
            let raw_server_fd =
                create_unix_server_socket(&task, addr.clone(), SockFlags::empty()).unwrap();
            let raw_client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            let server_fd = typed_socket(&task, raw_server_fd);
            let client_fd = typed_socket(&task, raw_client_fd);
            task.do_connect(&client_fd, SocketAddress::Unix(addr))
                .unwrap();

            let mut peer_addr = SocketAddress::default();
            let raw_server_conn = task
                .do_accept(&server_fd, Some(&mut peer_addr), SockFlags::empty())
                .unwrap();
            let server_conn = typed_socket(&task, raw_server_conn);
            assert!(matches!(
                peer_addr,
                SocketAddress::Unix(UnixSocketAddr::Unnamed)
            ));
            assert_eq!(
                task.do_sendto(&server_conn, &[], SendFlags::empty(), None)
                    .expect("zero-length sendto failed"),
                0
            );
            let msg1 = "Hello, ";
            let n = task
                .do_sendto(&server_conn, msg1.as_bytes(), SendFlags::empty(), None)
                .expect("sendto failed");
            assert_eq!(n, msg1.len());
            let msg2 = "world!";
            let n = task
                .do_sendto(&server_conn, msg2.as_bytes(), SendFlags::empty(), None)
                .expect("sendto failed");
            assert_eq!(n, msg2.len());

            let mut buf = [0u8; 64];
            let n = task
                .do_recvfrom(&client_fd, &mut buf, ReceiveFlags::PEEK, None)
                .expect("peek failed");
            assert_eq!(n, msg1.len() + msg2.len());
            assert_eq!(&buf[..n], b"Hello, world!");
            let n = task
                .do_recvfrom(&client_fd, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(n, msg1.len() + msg2.len());
            assert_eq!(&buf[..n], b"Hello, world!");

            close_socket(&task, raw_server_fd);
            close_socket(&task, raw_client_fd);
            close_socket(&task, raw_server_conn);
        }
    }

    #[test]
    fn test_unix_stream_socket_refused() {
        let task = init_platform();
        let raw_client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let client_fd = typed_socket(&task, raw_client_fd);
        let addr = "/unix_stream_socket_refused.sock";
        let result = task.do_connect(
            &client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
        close_socket(&task, raw_client_fd);

        let raw_server_fd = create_unix_server_socket(
            &task,
            UnixSocketAddr::Path(addr.to_string()),
            SockFlags::empty(),
        )
        .unwrap();
        let raw_client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let client_fd = typed_socket(&task, raw_client_fd);
        let result = task.do_connect(
            &client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert!(result.is_ok());

        // close the server socket
        close_socket(&task, raw_server_fd);

        let raw_another_client = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let another_client = typed_socket(&task, raw_another_client);
        let result = task.do_connect(
            &another_client,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert_eq!(result.unwrap_err(), Errno::ECONNREFUSED);

        close_socket(&task, raw_another_client);
        close_socket(&task, raw_client_fd);

        let addr = "/unix_stream_socket_refused2.sock";
        let raw_server_fd = create_unix_server_socket(
            &task,
            UnixSocketAddr::Path(addr.to_string()),
            SockFlags::empty(),
        )
        .unwrap();
        let raw_client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let client_fd = typed_socket(&task, raw_client_fd);

        // remove the sock file
        task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
        let result = task.do_connect(
            &client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
        );
        assert_eq!(result.unwrap_err(), Errno::ENOENT);

        close_socket(&task, raw_server_fd);
        close_socket(&task, raw_client_fd);
        task.sys_unlinkat(-1, "/unix_stream_socket_refused.sock", AtFlags::empty())
            .unwrap();
    }

    fn test_multiple_unix_stream_connections(is_nonblocking: bool) {
        let task = init_platform();
        let addr = UnixSocketAddr::Abstract(b"multi-stream-socket".to_vec());
        let raw_server_fd = create_unix_server_socket(
            &task,
            addr.clone(),
            if is_nonblocking {
                SockFlags::NONBLOCK
            } else {
                SockFlags::empty()
            },
        )
        .unwrap();
        let server_fd = typed_socket(&task, raw_server_fd);

        let client_addr = addr.clone();
        let client = task.spawn_clone_for_test(move |task| {
            let mut client_fds = Vec::new();
            for _ in 0..10 {
                let raw_client_fd = create_unix_socket(
                    &task,
                    SockType::Stream,
                    if is_nonblocking {
                        SockFlags::NONBLOCK
                    } else {
                        SockFlags::empty()
                    },
                );
                let client_fd = typed_socket(&task, raw_client_fd);
                // A listener never polls writable, so a non-blocking connect
                // retries while the backlog is full.
                loop {
                    match task.do_connect(&client_fd, SocketAddress::Unix(client_addr.clone())) {
                        Ok(()) => break,
                        Err(Errno::EAGAIN) if is_nonblocking => std::thread::yield_now(),
                        Err(error) => panic!("connect failed: {error:?}"),
                    }
                }
                client_fds.push((raw_client_fd, client_fd));
            }

            for (i, (_, client_fd)) in client_fds.iter().enumerate() {
                let msg = alloc::format!("message from connection {i}");
                let n = task
                    .do_sendto(client_fd, msg.as_bytes(), SendFlags::empty(), None)
                    .expect("sendto failed");
                assert_eq!(n, msg.len());
            }

            for (raw_client_fd, _) in client_fds {
                close_socket(&task, raw_client_fd);
            }
        });

        let mut raw_server_conn_fds = Vec::new();
        for _ in 0..10 {
            if is_nonblocking {
                ppoll(&task, raw_server_fd, Events::IN);
            }
            let raw_server_conn_fd = task
                .do_accept(
                    &server_fd,
                    None,
                    if is_nonblocking {
                        SockFlags::NONBLOCK
                    } else {
                        SockFlags::empty()
                    },
                )
                .unwrap();
            raw_server_conn_fds.push(raw_server_conn_fd);
        }

        for (i, raw_server_conn_fd) in raw_server_conn_fds.iter().enumerate() {
            let msg = alloc::format!("message from connection {i}");
            let mut buf = [0u8; 64];
            if is_nonblocking {
                ppoll(&task, *raw_server_conn_fd, Events::IN);
            }
            let server_conn_fd = typed_socket(&task, *raw_server_conn_fd);
            let n = task
                .do_recvfrom(&server_conn_fd, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(n, msg.len());
            assert_eq!(&buf[..n], msg.as_bytes());
        }

        for raw_server_conn_fd in raw_server_conn_fds {
            close_socket(&task, raw_server_conn_fd);
        }
        close_socket(&task, raw_server_fd);
        client.join().unwrap();
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

            let raw_server1_fd = create_unix_server_socket(
                &task,
                UnixSocketAddr::Path(addr.to_string()),
                SockFlags::NONBLOCK,
            )
            .unwrap();
            let server1_fd = typed_socket(&task, raw_server1_fd);
            let err = create_unix_server_socket(
                &task,
                UnixSocketAddr::Path(addr.to_string()),
                SockFlags::empty(),
            )
            .unwrap_err();
            assert_eq!(err, Errno::EADDRINUSE);

            // remove the socket file to allow another server to bind to the same address
            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
            let raw_server2_fd = create_unix_server_socket(
                &task,
                UnixSocketAddr::Path(addr.to_string()),
                SockFlags::NONBLOCK,
            )
            .unwrap();
            let server2_fd = typed_socket(&task, raw_server2_fd);
            let raw_client1_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            let client1_fd = typed_socket(&task, raw_client1_fd);
            task.do_connect(
                &client1_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();

            // server one is still alive but cannot accept connections
            let err = task
                .do_accept(&server1_fd, None, SockFlags::empty())
                .unwrap_err();
            assert_eq!(err, Errno::EAGAIN);

            let conn_fd = task
                .do_accept(&server2_fd, None, SockFlags::empty())
                .unwrap();
            close_socket(&task, conn_fd);
            close_socket(&task, raw_client1_fd);

            // close server one and connect again
            close_socket(&task, raw_server1_fd);
            let raw_client2_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
            let client2_fd = typed_socket(&task, raw_client2_fd);
            task.do_connect(
                &client2_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();
            close_socket(&task, raw_client2_fd);
            close_socket(&task, raw_server2_fd);

            // still fail after we close the server
            let err = create_unix_server_socket(
                &task,
                UnixSocketAddr::Path(addr.to_string()),
                SockFlags::empty(),
            )
            .unwrap_err();
            assert_eq!(err, Errno::EADDRINUSE);

            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
        }
    }

    #[test]
    fn test_unix_datagram_socket_on_same_addr() {
        let task = init_platform();
        for _ in 0..10 {
            let addr = "/unix_datagram_socket_server.sock";
            let raw_server_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let server_fd = typed_socket(&task, raw_server_fd);
            task.do_bind(
                &server_fd,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();

            let raw_server_fd2 = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let server_fd2 = typed_socket(&task, raw_server_fd2);
            let err = task
                .do_bind(
                    &server_fd2,
                    SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
                )
                .unwrap_err();
            assert_eq!(err, Errno::EADDRINUSE);
            close_socket(&task, raw_server_fd2);

            task.sys_unlinkat(-1, addr, AtFlags::empty()).unwrap();
            let raw_server_fd2 = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
            let server_fd2 = typed_socket(&task, raw_server_fd2);
            task.do_bind(
                &server_fd2,
                SocketAddress::Unix(UnixSocketAddr::Path(addr.to_string())),
            )
            .unwrap();

            close_socket(&task, raw_server_fd);
            close_socket(&task, raw_server_fd2);
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

        let raw_sock1 = sv_ptr[0];
        let raw_sock2 = sv_ptr[1];
        let sock1 = typed_socket(&task, raw_sock1);
        let sock2 = typed_socket(&task, raw_sock2);

        // Receive on sock2 (from sock1)
        let receiver2 = task.spawn_clone_for_test(move |task| {
            let mut buf = [0u8; 64];
            if is_nonblocking {
                ppoll(&task, raw_sock2, Events::IN);
            }
            let sock2 = typed_socket(&task, raw_sock2);
            let n = task
                .do_recvfrom(&sock2, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(&buf[..n], b"Message from sock1");
        });

        std::thread::sleep(core::time::Duration::from_millis(100));
        // Send from sock1 to sock2
        let msg1 = "Message from sock1";
        task.do_sendto(&sock1, msg1.as_bytes(), SendFlags::empty(), None)
            .expect("sendto failed");

        let receiver1 = task.spawn_clone_for_test(move |task| {
            // Receive on sock1 (from sock2)
            let mut buf = [0u8; 64];
            if is_nonblocking {
                ppoll(&task, raw_sock1, Events::IN);
            }
            let sock1 = typed_socket(&task, raw_sock1);
            let n = task
                .do_recvfrom(&sock1, &mut buf, ReceiveFlags::empty(), None)
                .expect("recvfrom failed");
            assert_eq!(&buf[..n], b"Message from sock2");
        });

        std::thread::sleep(core::time::Duration::from_millis(100));
        // Send from sock2 to sock1
        let msg2 = "Message from sock2";
        task.do_sendto(&sock2, msg2.as_bytes(), SendFlags::empty(), None)
            .expect("sendto failed");

        std::thread::sleep(core::time::Duration::from_millis(500));
        close_socket(&task, raw_sock1);
        close_socket(&task, raw_sock2);
        receiver2.join().unwrap();
        receiver1.join().unwrap();
    }

    #[test]
    fn test_unix_socketpair_bidirectional() {
        unix_socketpair_bidirectional(SockType::Stream, false);
        unix_socketpair_bidirectional(SockType::Datagram, false);

        unix_socketpair_bidirectional(SockType::Stream, true);
        unix_socketpair_bidirectional(SockType::Datagram, true);
    }

    #[test]
    fn unix_paths_may_omit_the_nul_terminator() {
        let parse = |name: &[u8]| {
            let mut address = (AddressFamily::UNIX as u16).to_ne_bytes().to_vec();
            address.extend_from_slice(name);
            read_sockaddr_from_user::<crate::syscalls::tests::TestPlatform>(
                UserPtr::from_ptr(address.as_ptr()),
                address.len(),
            )
        };
        let path = |name: &str| Ok(SocketAddress::Unix(UnixSocketAddr::Path(name.to_string())));
        // `addrlen = SUN_LEN(addr)` excludes the NUL, so the path ends at `addrlen`.
        assert_eq!(parse(b"/sun_len.sock"), path("/sun_len.sock"));
        assert_eq!(parse(b"/sun_len.sock\0ignored"), path("/sun_len.sock"));
        // Linux's `sizeof(((struct sockaddr_un *)0)->sun_path)`.
        let path_max = 108;
        let longest = "a".repeat(path_max);
        assert_eq!(parse(longest.as_bytes()), path(&longest));
        let too_long = "a".repeat(path_max + 1);
        assert_eq!(parse(too_long.as_bytes()), Err(Errno::EINVAL));
    }

    #[test]
    fn unix_datagram_reads_and_vectors_keep_boundaries() {
        use litebox_common_linux::{IoReadVec, IoWriteVec};

        let task = init_platform();
        // Non-blocking, so a split `readv` fails rather than waiting for another datagram.
        let (sender, receiver) = task
            .do_socketpair(
                AddressFamily::UNIX,
                SockType::Datagram,
                SockFlags::NONBLOCK,
                0,
            )
            .unwrap();
        let sender_fd = i32::try_from(sender).unwrap();
        let receiver_fd = i32::try_from(receiver).unwrap();

        let (first, second) = (b"ab", b"cdef");
        let write_iovs = [
            IoWriteVec {
                iov_base: UserPtr::from_usize(first.as_ptr().expose_provenance()),
                iov_len: first.len(),
            },
            IoWriteVec {
                iov_base: UserPtr::from_usize(second.as_ptr().expose_provenance()),
                iov_len: second.len(),
            },
        ];
        let write_iovs_ptr = UserPtr::from_usize(write_iovs.as_ptr().expose_provenance());
        assert_eq!(task.sys_writev(sender_fd, write_iovs_ptr, 2), Ok(6));
        assert_eq!(task.sys_writev(sender_fd, write_iovs_ptr, 2), Ok(6));

        let mut short = [0; 3];
        assert_eq!(task.sys_read(receiver_fd, &mut short, None), Ok(3));
        assert_eq!(&short, b"abc");

        let (mut head, mut tail) = ([0; 1], [0; 8]);
        let read_iovs = [
            IoReadVec {
                iov_base: UserPtrMut::from_usize(head.as_mut_ptr().expose_provenance()),
                iov_len: head.len(),
            },
            IoReadVec {
                iov_base: UserPtrMut::from_usize(tail.as_mut_ptr().expose_provenance()),
                iov_len: tail.len(),
            },
        ];
        let read_iovs_ptr = UserPtr::from_usize(read_iovs.as_ptr().expose_provenance());
        assert_eq!(task.sys_readv(receiver_fd, read_iovs_ptr, 2), Ok(6));
        assert_eq!(&head, b"a");
        assert_eq!(&tail[..5], b"bcdef");

        let receiver_typed = typed_socket(&task, receiver);
        assert_eq!(
            task.do_recvfrom(&receiver_typed, &mut short, ReceiveFlags::DONTWAIT, None),
            Err(Errno::EAGAIN)
        );
        close_socket(&task, sender);
        close_socket(&task, receiver);
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
        let (received, _) = task
            .do_recvfrom_with_copy(&socket, &mut old, ReceiveFlags::empty(), None, false, None)
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

    #[test]
    fn test_socketpair_race_with_concurrent_close() {
        let task = init_platform();
        task.files.borrow().set_max_fd(4);

        let stop = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let stop_closer = stop.clone();
        let closer = task.spawn_clone_for_test(move |task| {
            while !stop_closer.load(core::sync::atomic::Ordering::Relaxed) {
                let _ = task.sys_close(3);
            }
        });

        for iter in 0..50_000 {
            assert_eq!(
                task.do_socketpair(AddressFamily::UNIX, SockType::Stream, SockFlags::empty(), 0),
                Err(Errno::EMFILE),
                "failed at iteration {iter}"
            );
        }

        stop.store(true, core::sync::atomic::Ordering::Relaxed);
        closer.join().unwrap();
    }

    fn unix_socket_recv_timeout(ty: SockType) {
        let task = init_platform();
        let (raw_sock1, _raw_sock2) = task
            .do_socketpair(AddressFamily::UNIX, ty, SockFlags::empty(), 0)
            .expect("socketpair failed");
        let sock1 = typed_socket(&task, raw_sock1);
        let timeout = Duration::from_millis(200);
        let tv = litebox_common_linux::TimeVal::from(timeout);
        let optval = UserPtr::from_usize((&raw const tv).cast::<u8>() as usize);
        task.do_setsockopt(
            &sock1,
            SocketOptionName::Socket(SocketOption::RCVTIMEO),
            optval,
            core::mem::size_of::<litebox_common_linux::TimeVal>(),
        )
        .expect("Failed to set SO_RCVTIMEO");
        let mut buf = [0u8; 16];
        let start = std::time::Instant::now();
        let err = task
            .do_recvfrom(&sock1, &mut buf, ReceiveFlags::empty(), None)
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
    fn unix_dgram_epipe_does_not_raise_sigpipe() {
        use litebox_common_linux::signal::Signal;

        let task = init_platform();
        // A raised SIGPIPE stays pending, so the stream socket comes last.
        for (ty, raises) in [(SockType::Datagram, false), (SockType::Stream, true)] {
            let (sender, receiver) = task
                .do_socketpair(AddressFamily::UNIX, ty, SockFlags::empty(), 0)
                .unwrap();
            let sender_fd = i32::try_from(sender).unwrap();
            task.sys_shutdown(sender_fd, litebox_common_linux::ShutdownHow::Write as i32)
                .unwrap();
            assert_eq!(task.sys_write(sender_fd, b"x", None), Err(Errno::EPIPE));
            let data = b"y";
            assert_eq!(
                task.sys_sendto(
                    sender_fd,
                    UserPtr::from_usize(data.as_ptr().expose_provenance()),
                    data.len(),
                    SendFlags::empty(),
                    None,
                    0,
                ),
                Err(Errno::EPIPE)
            );
            assert_eq!(
                task.pending_signal_set().contains(Signal::SIGPIPE),
                raises,
                "{ty:?}"
            );
            close_socket(&task, sender);
            close_socket(&task, receiver);
        }
    }

    #[test]
    fn unix_addresses_are_truncated_to_the_callers_buffer() {
        let task = init_platform();
        let path = "/unix_truncated_name.sock";
        let raw_fd = create_unix_server_socket(
            &task,
            UnixSocketAddr::Path(path.to_string()),
            SockFlags::empty(),
        )
        .unwrap();
        let fd = i32::try_from(raw_fd).unwrap();
        let mut expected = (AddressFamily::UNIX as u16).to_ne_bytes().to_vec();
        expected.extend_from_slice(path.as_bytes());
        expected.push(0);
        let full_length = u32::try_from(expected.len()).unwrap();
        for capacity in [0, 1, 3, full_length] {
            let mut buffer = [0xff_u8; 64];
            let mut length = capacity;
            task.sys_getsockname(
                fd,
                UserPtrMut::from_ptr(buffer.as_mut_ptr()),
                UserPtrMut::from_ptr(&raw mut length),
            )
            .unwrap();
            assert_eq!(length, full_length);
            let copied = capacity as usize;
            assert_eq!(&buffer[..copied], &expected[..copied]);
            assert!(buffer[copied..].iter().all(|&byte| byte == 0xff));
        }
        close_socket(&task, raw_fd);
        task.sys_unlinkat(-1, path, AtFlags::empty()).unwrap();
    }

    #[test]
    fn test_unix_stream_addr() {
        let task = init_platform();
        let server_path = "/unix_stream_sockname.sock";
        let raw_server_fd = create_unix_server_socket(
            &task,
            UnixSocketAddr::Path(server_path.to_string()),
            SockFlags::empty(),
        )
        .unwrap();
        let server_fd = typed_socket(&task, raw_server_fd);

        // Server socket should have its bound address
        let server_addr = task.do_getsockname(&server_fd).unwrap();
        assert_eq!(
            server_addr,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Create client and connect
        let raw_client_fd = create_unix_socket(&task, SockType::Stream, SockFlags::empty());
        let client_fd = typed_socket(&task, raw_client_fd);

        // Before connect, client should have unnamed address
        let client_addr = task.do_getsockname(&client_fd).unwrap();
        assert!(matches!(
            client_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));
        // Connect client to server
        // Connect client to server
        task.do_connect(
            &client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .unwrap();

        // After connect, client's getsockname should still be unnamed
        let client_local_addr = task.do_getsockname(&client_fd).unwrap();
        assert!(matches!(
            client_local_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        // Client's getpeername should return server's address
        let client_peer_addr = task.do_getpeername(&client_fd).unwrap();
        assert_eq!(
            client_peer_addr,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Accept connection on server
        let raw_server_conn = task
            .do_accept(&server_fd, None, SockFlags::empty())
            .unwrap();
        let server_conn = typed_socket(&task, raw_server_conn);

        // Server connection's local address should be the server's bound address
        let server_conn_local = task.do_getsockname(&server_conn).unwrap();
        assert_eq!(
            server_conn_local,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Server connection's peer address should be unnamed (client didn't bind)
        let server_conn_peer = task.do_getpeername(&server_conn).unwrap();
        assert!(matches!(
            server_conn_peer,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        close_socket(&task, raw_client_fd);
        close_socket(&task, raw_server_conn);
        close_socket(&task, raw_server_fd);
        task.sys_unlinkat(-1, server_path, AtFlags::empty())
            .unwrap();
    }

    #[test]
    fn test_unix_datagram_addr() {
        let task = init_platform();
        let server_path = "/unix_datagram_sockname_server.sock";
        let client_path = "/unix_datagram_sockname_client.sock";

        let raw_server_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
        let raw_client_fd = create_unix_socket(&task, SockType::Datagram, SockFlags::empty());
        let server_fd = typed_socket(&task, raw_server_fd);
        let client_fd = typed_socket(&task, raw_client_fd);

        // Before bind, both should have unnamed addresses
        let server_addr = task.do_getsockname(&server_fd).unwrap();
        assert!(matches!(
            server_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));

        let client_addr = task.do_getsockname(&client_fd).unwrap();
        assert!(matches!(
            client_addr,
            SocketAddress::Unix(UnixSocketAddr::Unnamed)
        ));
        // Bind server
        // Bind server
        task.do_bind(
            &server_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .unwrap();

        // After bind, server should have its bound address
        let server_local = task.do_getsockname(&server_fd).unwrap();
        assert_eq!(
            server_local,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );
        // Bind client
        // Bind client
        task.do_bind(
            &client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(client_path.to_string())),
        )
        .unwrap();

        // After bind, client should have its bound address
        let client_local = task.do_getsockname(&client_fd).unwrap();
        assert_eq!(
            client_local,
            SocketAddress::Unix(UnixSocketAddr::Path(client_path.to_string()))
        );
        // Connect client to server
        // Connect client to server
        task.do_connect(
            &client_fd,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string())),
        )
        .unwrap();

        // After connect, getsockname should still return client's bound address
        let client_local_after_connect = task.do_getsockname(&client_fd).unwrap();
        assert_eq!(
            client_local_after_connect,
            SocketAddress::Unix(UnixSocketAddr::Path(client_path.to_string()))
        );

        // getpeername should return server's address
        let client_peer = task.do_getpeername(&client_fd).unwrap();
        assert_eq!(
            client_peer,
            SocketAddress::Unix(UnixSocketAddr::Path(server_path.to_string()))
        );

        // Server hasn't connected, so getpeername should fail with ENOTCONN
        let server_peer_result = task.do_getpeername(&server_fd);
        assert_eq!(server_peer_result.unwrap_err(), Errno::ENOTCONN);

        close_socket(&task, raw_server_fd);
        close_socket(&task, raw_client_fd);
        task.sys_unlinkat(-1, server_path, AtFlags::empty())
            .unwrap();
        task.sys_unlinkat(-1, client_path, AtFlags::empty())
            .unwrap();
    }
}
