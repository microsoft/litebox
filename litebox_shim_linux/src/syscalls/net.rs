//! Socket-related syscalls, e.g., socket, bind, listen, etc.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use litebox::{
    fs::OFlags,
    net::TcpOptionData,
    platform::{RawConstPointer as _, RawMutPointer as _},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption, SocketOptionName,
    TcpOption, errno::Errno,
};

use crate::Task;
use crate::{ConstPtr, Descriptor, MutPtr, litebox_net};
use crate::{Platform, litebox};

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

pub(super) type SocketFd = litebox::net::SocketFd<Platform>;

impl super::file::FilesState {
    fn with_socket_fd<R>(
        &self,
        raw_fd: usize,
        f: impl FnOnce(&SocketFd) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let rds = self.raw_descriptor_store.read();
        match rds.fd_from_raw_integer(raw_fd) {
            Ok(fd) => {
                drop(rds);
                f(&fd)
            }
            Err(litebox::fd::ErrRawIntFd::NotFound) => Err(Errno::EBADF),
            Err(litebox::fd::ErrRawIntFd::InvalidSubsystem) => Err(Errno::ENOTSOCK),
        }
    }
}

#[derive(Clone, Copy)]
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
}

impl Default for SocketAddress {
    fn default() -> Self {
        SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    }
}

#[derive(Default)]
struct SocketOptions {
    reuse_address: bool,
    keep_alive: bool,
    /// Receiving timeout, None (default value) means no timeout
    recv_timeout: Option<core::time::Duration>,
    /// Sending timeout, None (default value) means no timeout
    send_timeout: Option<core::time::Duration>,
    /// Linger timeout, None (default value) means closing in the background.
    /// If it is `Some`, a close or shutdown will not return
    /// until all queued messages for the socket have been
    /// successfully sent or the timeout has been reached.
    linger_timeout: Option<core::time::Duration>,
}

pub(crate) struct SocketOFlags(pub OFlags);

fn initialize_socket(fd: &SocketFd, sock_type: SockType, flags: SockFlags) {
    let mut status = OFlags::RDWR;
    status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));

    let mut dt = litebox().descriptor_table_mut();
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
}

fn with_socket_options<R>(fd: &SocketFd, f: impl FnOnce(&SocketOptions) -> R) -> R {
    litebox()
        .descriptor_table()
        .with_metadata(fd, |opt| f(opt))
        .unwrap()
}
fn with_socket_options_mut<R>(fd: &SocketFd, f: impl FnOnce(&mut SocketOptions) -> R) -> R {
    litebox()
        .descriptor_table_mut()
        .with_metadata_mut(fd, |opt| f(opt))
        .unwrap()
}

fn setsockopt(
    fd: &SocketFd,
    optname: SocketOptionName,
    optval: ConstPtr<u8>,
    optlen: usize,
) -> Result<(), Errno> {
    match optname {
        SocketOptionName::IP(ip) => match ip {
            litebox_common_linux::IpOption::TOS => Err(Errno::EOPNOTSUPP),
        },
        SocketOptionName::Socket(so) => {
            let read_timeval_as_duration =
                |optval: ConstPtr<_>| -> Result<Option<core::time::Duration>, Errno> {
                    if optlen < size_of::<litebox_common_linux::TimeVal>() {
                        return Err(Errno::EINVAL);
                    }
                    let optval: ConstPtr<litebox_common_linux::TimeVal> =
                        ConstPtr::from_usize(optval.as_usize());
                    let timeval = unsafe { optval.read_at_offset(0) }
                        .ok_or(Errno::EFAULT)?
                        .into_owned();
                    let d = core::time::Duration::try_from(timeval)?;
                    if d.is_zero() { Ok(None) } else { Ok(Some(d)) }
                };
            match so {
                SocketOption::RCVTIMEO => {
                    let duration = read_timeval_as_duration(optval)?;
                    with_socket_options_mut(fd, |opt| {
                        opt.recv_timeout = duration;
                    });
                    return Ok(());
                }
                SocketOption::SNDTIMEO => {
                    let duration = read_timeval_as_duration(optval)?;
                    with_socket_options_mut(fd, |opt| {
                        opt.send_timeout = duration;
                    });
                    return Ok(());
                }
                SocketOption::LINGER => {
                    if optlen < size_of::<litebox_common_linux::Linger>() {
                        return Err(Errno::EINVAL);
                    }
                    let linger: crate::ConstPtr<litebox_common_linux::Linger> =
                        crate::ConstPtr::from_usize(optval.as_usize());
                    let linger = unsafe { linger.read_at_offset(0) }.ok_or(Errno::EFAULT)?;
                    // TODO: our current implementation of `close` does not support graceful close yet.
                    if linger.onoff != 0 && linger.linger != 0 {
                        unimplemented!("SO_LINGER with non-zero timeout is not supported yet");
                    }
                    return Ok(());
                }
                _ => {}
            }

            if optlen < size_of::<u32>() {
                return Err(Errno::EINVAL);
            }
            let optval: ConstPtr<u32> = ConstPtr::from_usize(optval.as_usize());
            let val = unsafe { optval.read_at_offset(0) }
                .ok_or(Errno::EFAULT)?
                .into_owned();
            match so {
                SocketOption::REUSEADDR => {
                    with_socket_options_mut(fd, |opt| {
                        opt.reuse_address = val != 0;
                    });
                }
                SocketOption::BROADCAST => {
                    if val == 0 {
                        todo!("disable SO_BROADCAST");
                    }
                }
                SocketOption::KEEPALIVE => {
                    let keep_alive = val != 0;
                    if let Err(err) = litebox_net().lock().set_tcp_option(
                        fd,
                        // default time interval is 2 hours
                        litebox::net::TcpOptionData::KEEPALIVE(Some(
                            core::time::Duration::from_secs(2 * 60 * 60),
                        )),
                    ) {
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
                    with_socket_options_mut(fd, |opt| {
                        opt.keep_alive = keep_alive;
                    });
                }
                // We use fixed buffer size for now
                SocketOption::RCVBUF | SocketOption::SNDBUF => return Err(Errno::EOPNOTSUPP),
                // Already handled at the beginning
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO | SocketOption::LINGER => {}
                // Socket does not support these options
                SocketOption::TYPE | SocketOption::PEERCRED => return Err(Errno::ENOPROTOOPT),
            }
            Ok(())
        }
        SocketOptionName::TCP(to) => {
            let optval: ConstPtr<u32> = ConstPtr::from_usize(optval.as_usize());
            let val = unsafe { optval.read_at_offset(0) }
                .ok_or(Errno::EFAULT)?
                .into_owned();
            match to {
                TcpOption::NODELAY | TcpOption::CORK => {
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
                    litebox_net()
                        .lock()
                        .set_tcp_option(fd, litebox::net::TcpOptionData::NODELAY(on))?;
                    Ok(())
                }
                TcpOption::KEEPINTVL => {
                    const MAX_TCP_KEEPINTVL: u32 = 32767;
                    if !(1..=MAX_TCP_KEEPINTVL).contains(&val) {
                        return Err(Errno::EINVAL);
                    }
                    litebox_net()
                        .lock()
                        .set_tcp_option(
                            fd,
                            litebox::net::TcpOptionData::KEEPALIVE(Some(
                                core::time::Duration::from_secs(u64::from(val)),
                            )),
                        )
                        .expect("set TCP_KEEPALIVE should succeed");
                    Ok(())
                }
                TcpOption::KEEPCNT | TcpOption::KEEPIDLE => Err(Errno::EOPNOTSUPP),
                _ => unimplemented!("TCP option {to:?}"),
            }
        }
    }
}

fn getsockopt(
    fd: &SocketFd,
    optname: SocketOptionName,
    optval: MutPtr<u8>,
    optlen: MutPtr<u32>,
) -> Result<(), Errno> {
    let len = unsafe { optlen.read_at_offset(0).ok_or(Errno::EFAULT) }?.into_owned();
    if len > i32::MAX as u32 {
        return Err(Errno::EINVAL);
    }
    let new_len = match optname {
        SocketOptionName::IP(ipopt) => match ipopt {
            litebox_common_linux::IpOption::TOS => return Err(Errno::EOPNOTSUPP),
        },
        SocketOptionName::Socket(sopt) => {
            match sopt {
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO | SocketOption::LINGER => {
                    let tv = with_socket_options(fd, |options| match sopt {
                        SocketOption::RCVTIMEO => options.recv_timeout,
                        SocketOption::SNDTIMEO => options.send_timeout,
                        SocketOption::LINGER => options.linger_timeout,
                        _ => unreachable!(),
                    })
                    .map_or_else(
                        litebox_common_linux::TimeVal::default,
                        litebox_common_linux::TimeVal::from,
                    );
                    // If the provided buffer is too small, we just write as much as we can.
                    let length = size_of::<litebox_common_linux::TimeVal>().min(len as usize);
                    let data = unsafe {
                        core::slice::from_raw_parts((&raw const tv).cast::<u8>(), length)
                    };
                    unsafe { optval.write_slice_at_offset(0, data) }.ok_or(Errno::EFAULT)?;
                    length
                }
                _ => {
                    let val = match sopt {
                        SocketOption::TYPE => get_socket_type(fd)? as u32,
                        SocketOption::REUSEADDR => {
                            u32::from(with_socket_options(fd, |o| o.reuse_address))
                        }
                        SocketOption::BROADCAST => 1, // TODO: We don't support disabling SO_BROADCAST
                        SocketOption::KEEPALIVE => {
                            u32::from(with_socket_options(fd, |o| o.keep_alive))
                        }
                        SocketOption::RCVBUF | SocketOption::SNDBUF => {
                            litebox::net::SOCKET_BUFFER_SIZE.truncate()
                        }
                        SocketOption::PEERCRED => return Err(Errno::ENOPROTOOPT),
                        SocketOption::RCVTIMEO | SocketOption::SNDTIMEO | SocketOption::LINGER => {
                            unreachable!()
                        }
                    };
                    // If the provided buffer is too small, we just write as much as we can.
                    let length = size_of::<u32>().min(len as usize);
                    let data = &val.to_ne_bytes()[..length];
                    unsafe { optval.write_slice_at_offset(0, data) }.ok_or(Errno::EFAULT)?;
                    length
                }
            }
        }
        SocketOptionName::TCP(tcpopt) => {
            let val: u32 = match tcpopt {
                TcpOption::KEEPINTVL => {
                    let TcpOptionData::KEEPALIVE(interval) = litebox_net()
                        .lock()
                        .get_tcp_option(fd, litebox::net::TcpOptionName::KEEPALIVE)?
                    else {
                        unreachable!()
                    };
                    interval.map_or(0, |d| d.as_secs().try_into().unwrap())
                }
                TcpOption::NODELAY | TcpOption::CORK => {
                    let TcpOptionData::NODELAY(nodelay) = litebox_net()
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
                TcpOption::KEEPCNT | TcpOption::KEEPIDLE => return Err(Errno::EOPNOTSUPP),
                TcpOption::CONGESTION | TcpOption::INFO => {
                    unimplemented!("TCP option {tcpopt:?}")
                }
            };
            let data = &val.to_ne_bytes()[..size_of::<u32>().min(len as usize)];
            unsafe { optval.write_slice_at_offset(0, data) }.ok_or(Errno::EFAULT)?;
            size_of::<u32>()
        }
    };
    unsafe { optlen.write_at_offset(0, new_len.truncate()) }.ok_or(Errno::EFAULT)?;
    Ok(())
}

fn try_accept(fd: &SocketFd, peer: Option<&mut SocketAddr>) -> Result<SocketFd, Errno> {
    litebox_net().lock().accept(fd, peer).map_err(Errno::from)
}

fn accept(fd: &SocketFd, mut peer: Option<&mut SocketAddr>) -> Result<SocketFd, Errno> {
    if get_status(fd).contains(OFlags::NONBLOCK) {
        try_accept(fd, peer)
    } else {
        // TODO: use `poll` instead of busy wait
        loop {
            match try_accept(fd, peer.as_deref_mut()) {
                Err(Errno::EAGAIN) => {}
                ret => return ret,
            }
            core::hint::spin_loop();
        }
    }
}

fn bind(fd: &SocketFd, sockaddr: SocketAddr) -> Result<(), Errno> {
    litebox_net()
        .lock()
        .bind(fd, &sockaddr)
        .map_err(Errno::from)
}

fn connect(fd: &SocketFd, sockaddr: SocketAddr) -> Result<(), Errno> {
    litebox_net()
        .lock()
        .connect(fd, &sockaddr)
        .map_err(Errno::from)
}

fn listen(fd: &SocketFd, backlog: u16) -> Result<(), Errno> {
    litebox_net()
        .lock()
        .listen(fd, backlog)
        .map_err(Errno::from)
}

fn try_sendto(
    fd: &SocketFd,
    buf: &[u8],
    flags: litebox::net::SendFlags,
    sockaddr: Option<SocketAddr>,
) -> Result<usize, Errno> {
    let n = litebox_net().lock().send(fd, buf, flags, sockaddr)?;
    if n == 0 { Err(Errno::EAGAIN) } else { Ok(n) }
}

pub(crate) fn sendto(
    fd: &SocketFd,
    buf: &[u8],
    flags: SendFlags,
    sockaddr: Option<SocketAddr>,
) -> Result<usize, Errno> {
    // Convert `SendFlags` to `litebox::net::SendFlags`
    // Note [`Network::send`] is non-blocking and `DONTWAIT` is handled below
    // so we don't convert `DONTWAIT` here.
    let new_flags = convert_flags!(
        flags,
        SendFlags,
        litebox::net::SendFlags,
        CONFIRM,
        DONTROUTE,
        EOR,
        MORE,
        NOSIGNAL,
        OOB,
    );

    if get_status(fd).contains(OFlags::NONBLOCK) || flags.contains(SendFlags::DONTWAIT) {
        try_sendto(fd, buf, new_flags, sockaddr)
    } else {
        let timeout = with_socket_options(fd, |opt| opt.send_timeout);
        if timeout.is_some() {
            todo!("send timeout");
        }

        // TODO: use `poll` instead of busy wait
        loop {
            match try_sendto(fd, buf, new_flags, sockaddr) {
                Err(Errno::EAGAIN) => {}
                ret => return ret,
            }
            core::hint::spin_loop();
        }
    }
}

fn try_receive(
    fd: &SocketFd,
    buf: &mut [u8],
    flags: litebox::net::ReceiveFlags,
    source_addr: Option<&mut Option<SocketAddr>>,
) -> Result<usize, Errno> {
    let n = litebox_net().lock().receive(fd, buf, flags, source_addr)?;
    if n == 0 { Err(Errno::EAGAIN) } else { Ok(n) }
}

pub(crate) fn receive(
    fd: &SocketFd,
    buf: &mut [u8],
    flags: ReceiveFlags,
    mut source_addr: Option<&mut Option<SocketAddr>>,
) -> Result<usize, Errno> {
    // Convert `ReceiveFlags` to [`litebox::net::ReceiveFlags`]
    // Note [`Network::receive`] is non-blocking and `DONTWAIT` is handled below
    // so we don't convert `DONTWAIT` here.
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
        match get_socket_type(fd)? {
            SockType::Datagram | SockType::Raw => {
                new_flags.insert(litebox::net::ReceiveFlags::TRUNC);
            }
            SockType::Stream => {
                new_flags.insert(litebox::net::ReceiveFlags::DISCARD);
            }
            _ => unimplemented!(),
        }
    }

    if get_status(fd).contains(OFlags::NONBLOCK) || flags.contains(ReceiveFlags::DONTWAIT) {
        try_receive(fd, buf, new_flags, source_addr)
    } else {
        let timeout = with_socket_options(fd, |opt| opt.recv_timeout);
        if timeout.is_some() {
            todo!("recv timeout");
        }

        // TODO: use `poll` instead of busy wait
        loop {
            match try_receive(fd, buf, new_flags, source_addr.as_deref_mut()) {
                Err(Errno::EAGAIN) => {}
                ret => return ret,
            }
            core::hint::spin_loop();
        }
    }
}

fn get_socket_type(fd: &SocketFd) -> Result<SockType, Errno> {
    crate::litebox()
        .descriptor_table()
        .with_metadata(fd, |sock_type: &SockType| *sock_type)
        .map_err(|e| match e {
            litebox::fd::MetadataError::NoSuchMetadata => Errno::ENOTSOCK,
            litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
        })
}

fn get_status(fd: &SocketFd) -> litebox::fs::OFlags {
    litebox()
        .descriptor_table()
        .with_metadata(fd, |SocketOFlags(flags)| *flags)
        .unwrap()
        & litebox::fs::OFlags::STATUS_FLAGS_MASK
}

impl Task {
    /// Handle syscall `socket`
    pub(crate) fn sys_socket(
        &self,
        domain: AddressFamily,
        ty: SockType,
        flags: SockFlags,
        protocol: Option<litebox_common_linux::Protocol>,
    ) -> Result<u32, Errno> {
        let files = self.files.borrow();
        let file = match domain {
            AddressFamily::INET => {
                let protocol = match ty {
                    SockType::Stream => {
                        if protocol.is_some_and(|p| p != litebox_common_linux::Protocol::TCP) {
                            return Err(Errno::EINVAL);
                        }
                        litebox::net::Protocol::Tcp
                    }
                    SockType::Datagram => {
                        if protocol.is_some_and(|p| p != litebox_common_linux::Protocol::UDP) {
                            return Err(Errno::EINVAL);
                        }
                        litebox::net::Protocol::Udp
                    }
                    SockType::Raw => todo!(),
                    _ => unimplemented!(),
                };
                let socket = litebox_net().lock().socket(protocol)?;
                initialize_socket(&socket, ty, flags);
                Descriptor::LiteBoxRawFd(
                    files
                        .raw_descriptor_store
                        .write()
                        .fd_into_raw_integer(socket),
                )
            }
            AddressFamily::UNIX => todo!(),
            AddressFamily::INET6 | AddressFamily::NETLINK => return Err(Errno::EAFNOSUPPORT),
            _ => unimplemented!(),
        };
        files
            .file_descriptors
            .write()
            .insert(self, file)
            .map_err(|desc| {
                self.do_close(desc)
                    .expect("closing descriptor should succeed");
                Errno::EMFILE
            })
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
    let family = unsafe { ptr.read_at_offset(0) }
        .ok_or(Errno::EFAULT)?
        .into_owned();
    let family = AddressFamily::try_from(u32::from(family)).map_err(|_| Errno::EAFNOSUPPORT)?;
    match family {
        AddressFamily::INET => {
            if addrlen < size_of::<CSockInetAddr>() {
                return Err(Errno::EINVAL);
            }
            let ptr: ConstPtr<CSockInetAddr> = ConstPtr::from_usize(sockaddr.as_usize());
            // Note it reads the first 2 bytes (i.e., sa_family) again, but it is not used.
            // SocketAddrV4 only needs the port and addr.
            let inet_addr = unsafe { ptr.read_at_offset(0) }
                .ok_or(Errno::EFAULT)?
                .into_owned();
            Ok(SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::from(
                inet_addr,
            ))))
        }
        _ => todo!("unsupported family {family:?}"),
    }
}

pub(crate) fn write_sockaddr_to_user(
    sock_addr: SocketAddress,
    addr: crate::MutPtr<u8>,
    addrlen: crate::MutPtr<u32>,
) -> Result<(), Errno> {
    let addrlen_val = unsafe { addrlen.read_at_offset(0) }
        .ok_or(Errno::EFAULT)?
        .into_owned();
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
            unsafe { addr.write_slice_at_offset(0, &bytes[..addrlen_val]) }.ok_or(Errno::EFAULT)?;
            size_of::<CSockInetAddr>()
        }
        SocketAddress::Inet(SocketAddr::V6(_)) => todo!("copy_sockaddr_to_user for IPv6"),
    }
    .truncate();
    unsafe { addrlen.write_at_offset(0, len) }.ok_or(Errno::EFAULT)
}

impl Task {
    /// Handle syscall `accept`
    pub(crate) fn sys_accept(
        &self,
        sockfd: i32,
        peer: Option<&mut SocketAddress>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let socket = file_table.get_fd(sockfd).ok_or(Errno::EBADF)?;
        let file = match socket {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                files.with_socket_fd(*raw_fd, |fd| {
                    drop(file_table); // Drop before possibly-blocking `accept`
                    let sock_type = get_socket_type(fd)?;
                    let mut socket_addr = peer
                        .is_some()
                        .then(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
                    let accepted_fd = accept(fd, socket_addr.as_mut())?;
                    if let (Some(peer), Some(socket_addr)) = (peer, socket_addr) {
                        *peer = SocketAddress::Inet(socket_addr);
                    }

                    initialize_socket(&accepted_fd, sock_type, flags);
                    Ok(Descriptor::LiteBoxRawFd(
                        files
                            .raw_descriptor_store
                            .write()
                            .fd_into_raw_integer(accepted_fd),
                    ))
                })?
            }
            _ => return Err(Errno::ENOTSOCK),
        };
        files
            .file_descriptors
            .write()
            .insert(self, file)
            .map_err(|desc| {
                self.do_close(desc)
                    .expect("closing descriptor should succeed");
                Errno::EMFILE
            })
    }

    /// Handle syscall `connect`
    pub(crate) fn sys_connect(&self, fd: i32, sockaddr: SocketAddress) -> Result<(), Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(fd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                let SocketAddress::Inet(addr) = sockaddr;
                connect(fd, addr)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `bind`
    pub(crate) fn sys_bind(&self, sockfd: i32, sockaddr: SocketAddress) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                let SocketAddress::Inet(addr) = sockaddr;
                bind(fd, addr)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `listen`
    pub(crate) fn sys_listen(&self, sockfd: i32, backlog: u16) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                files.with_socket_fd(*raw_fd, |fd| listen(fd, backlog))
            }
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `sendto`
    pub(crate) fn sys_sendto(
        &self,
        fd: i32,
        buf: ConstPtr<u8>,
        len: usize,
        flags: SendFlags,
        sockaddr: Option<SocketAddress>,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let buf = unsafe { buf.to_cow_slice(len).ok_or(Errno::EFAULT) }?;
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let socket = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match socket {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                let sockaddr = sockaddr.map(|SocketAddress::Inet(addr)| addr);
                drop(file_table); // Drop before possibly-blocking `sendto`
                sendto(fd, &buf, flags, sockaddr)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `recvfrom`
    pub(crate) fn sys_recvfrom(
        &self,
        fd: i32,
        buf: MutPtr<u8>,
        len: usize,
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        match file_table.get_fd(fd).ok_or(Errno::EBADF)? {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                const MAX_LEN: usize = 4096;
                let mut buffer: [u8; MAX_LEN] = [0; MAX_LEN];
                let buffer: &mut [u8] = &mut buffer[..MAX_LEN.min(len)];
                let mut addr = None;
                drop(file_table); // Drop before possibly-blocking `receive`
                let size = receive(
                    fd,
                    buffer,
                    flags,
                    if source_addr.is_some() {
                        Some(&mut addr)
                    } else {
                        None
                    },
                )?;
                if let Some(source_addr) = source_addr {
                    *source_addr = addr.map(SocketAddress::Inet);
                }
                if !flags.contains(ReceiveFlags::TRUNC) {
                    assert!(size <= len, "{size} should be smaller than {len}");
                }
                buf.copy_from_slice(0, &buffer[..size.min(buffer.len())])
                    .ok_or(Errno::EFAULT)?;
                Ok(size)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    pub(crate) fn sys_setsockopt(
        &self,
        sockfd: i32,
        optname: SocketOptionName,
        optval: ConstPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                files.with_socket_fd(*raw_fd, |fd| setsockopt(fd, optname, optval, optlen))
            }
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `getsockopt`
    pub(crate) fn sys_getsockopt(
        &self,
        sockfd: i32,
        optname: SocketOptionName,
        optval: MutPtr<u8>,
        optlen: MutPtr<u32>,
    ) -> Result<(), Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                files.with_socket_fd(*raw_fd, |fd| getsockopt(fd, optname, optval, optlen))
            }
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `getsockname`
    pub(crate) fn sys_getsockname(&self, sockfd: i32) -> Result<SocketAddress, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                litebox_net()
                    .lock()
                    .get_local_addr(fd)
                    .map(SocketAddress::Inet)
                    .map_err(Errno::from)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `getpeername`
    pub(crate) fn sys_getpeername(&self, sockfd: i32) -> Result<SocketAddress, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };

        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                litebox_net()
                    .lock()
                    .get_remote_addr(fd)
                    .map(SocketAddress::Inet)
                    .map_err(Errno::from)
            }),
            _ => Err(Errno::ENOTSOCK),
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
    use litebox_common_linux::{AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType};

    use super::SocketAddress;
    use crate::ConstPtr;

    extern crate alloc;
    extern crate std;

    const TUN_IP_ADDR: [u8; 4] = [10, 0, 0, 2];
    const TUN_IP_ADDR_STR: &str = "10.0.0.2";
    const SERVER_PORT: u16 = 8080;
    const CLIENT_PORT: u16 = 8081;

    fn init_platform(tun_device_name: Option<&str>) -> crate::Task {
        let task = crate::syscalls::tests::init_platform(tun_device_name);
        // Start a background thread to perform network interaction
        // Naive implementation for testing purpose only
        std::thread::spawn(|| {
            loop {
                while crate::perform_network_interaction().call_again_immediately() {}
                core::hint::spin_loop();
            }
        });
        task
    }

    fn epoll_add(task: &crate::Task, epfd: i32, target_fd: i32, events: litebox::event::Events) {
        let ev = litebox_common_linux::EpollEvent {
            events: events.bits(),
            data: u64::try_from(target_fd).unwrap(),
        };
        let ev_ptr = (&raw const ev).cast::<litebox_common_linux::EpollEvent>();
        let ev_const = crate::ConstPtr::from_usize(ev_ptr as usize);
        task.sys_epoll_ctl(
            epfd,
            litebox_common_linux::EpollOp::EpollCtlAdd,
            target_fd,
            ev_const,
        )
        .expect("epoll_ctl add server failed");
    }

    fn epoll_wait(
        task: &crate::Task,
        epfd: i32,
        events: &mut [litebox_common_linux::EpollEvent],
    ) -> usize {
        let events_ptr = crate::MutPtr::from_usize(events.as_mut_ptr() as usize);
        task.sys_epoll_pwait(epfd, events_ptr, events.len().truncate(), -1, None, 0)
            .expect("epoll_wait failed")
    }

    fn test_tcp_socket(
        task: &crate::Task,
        ip: [u8; 4],
        port: u16,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &'static str,
    ) {
        let server = task
            .sys_socket(
                AddressFamily::INET,
                SockType::Stream,
                if is_nonblocking {
                    SockFlags::NONBLOCK
                } else {
                    SockFlags::empty()
                },
                None,
            )
            .unwrap();
        let server = i32::try_from(server).unwrap();
        let server_sockaddr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(ip),
            port,
        )));
        task.sys_bind(server, server_sockaddr.clone())
            .expect("Failed to bind socket");
        task.sys_listen(server, 1)
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
                "sendto" => std::process::Command::new("nc")
                    .args([
                        "-w", // timeout for connects and final net reads
                        "1",
                        TUN_IP_ADDR_STR,
                        SERVER_PORT.to_string().as_str(),
                    ])
                    .stdout(std::process::Stdio::piped())
                    .output(),
                "recvfrom" => std::process::Command::new("sh")
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
                assert!(ev.events & litebox::event::Events::IN.bits() != 0);
            }
        }

        let mut remote_addr = super::SocketAddress::default();
        let client_fd = task
            .sys_accept(
                server,
                Some(&mut remote_addr),
                if is_nonblocking {
                    SockFlags::NONBLOCK
                } else {
                    SockFlags::empty()
                },
            )
            .expect("Failed to accept connection");
        let client_fd = i32::try_from(client_fd).unwrap();
        assert_eq!(server_sockaddr, task.sys_getsockname(client_fd).unwrap());
        assert_eq!(remote_addr, task.sys_getpeername(client_fd).unwrap());
        let super::SocketAddress::Inet(SocketAddr::V4(remote_addr)) = remote_addr else {
            panic!("Expected IPv4 address");
        };
        assert_eq!(remote_addr.ip().octets(), [10, 0, 0, 1]);
        assert_ne!(remote_addr.port(), 0);

        match option {
            "sendto" => {
                let ptr = ConstPtr::from_usize(buf.as_ptr().expose_provenance());
                let n = task
                    .sys_sendto(client_fd, ptr, buf.len(), SendFlags::empty(), None)
                    .expect("Failed to send data");
                assert_eq!(n, buf.len());
                let output = child_handle
                    .join()
                    .unwrap()
                    .expect("Failed to wait for client");
                let stdout = alloc::string::String::from_utf8_lossy(&output.stdout);
                assert_eq!(stdout, buf);
            }
            "recvfrom" => {
                if is_nonblocking {
                    epoll_add(task, epfd, client_fd, litebox::event::Events::IN);
                    let mut events = [litebox_common_linux::EpollEvent { events: 0, data: 0 }; 2];
                    let n = epoll_wait(task, epfd, &mut events);
                    assert_eq!(n, 1);
                    for ev in &events[..n] {
                        assert!(ev.events & litebox::event::Events::IN.bits() != 0);
                        let fd = i32::try_from(ev.data).unwrap();
                        assert_eq!(fd, client_fd);
                    }
                }
                let mut recv_buf = [0u8; 48];
                let recv_ptr = crate::MutPtr::from_usize(recv_buf.as_mut_ptr() as usize);
                let n = task
                    .sys_recvfrom(
                        client_fd,
                        recv_ptr,
                        recv_buf.len(),
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
            _ => panic!("Unknown option"),
        }

        task.sys_close(client_fd)
            .expect("Failed to close client socket");
        task.sys_close(server)
            .expect("Failed to close server socket");
    }

    fn test_tcp_socket_with_external_client(
        port: u16,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &'static str,
    ) {
        let task = init_platform(Some("tun99"));
        test_tcp_socket(&task, TUN_IP_ADDR, port, is_nonblocking, test_trunc, option);
    }

    #[test]
    fn test_tun_blocking_sendto_tcp_socket() {
        test_tcp_socket_with_external_client(SERVER_PORT, false, false, "sendto");
    }

    #[test]
    fn test_tun_nonblocking_sendto_tcp_socket() {
        test_tcp_socket_with_external_client(SERVER_PORT, true, false, "sendto");
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

    fn blocking_udp_server_socket(test_trunc: bool, is_nonblocking: bool) {
        let task = init_platform(Some("tun99"));

        // Server socket and bind
        let server_fd = task
            .sys_socket(
                AddressFamily::INET,
                SockType::Datagram,
                if is_nonblocking {
                    SockFlags::NONBLOCK
                } else {
                    SockFlags::empty()
                },
                Some(litebox_common_linux::Protocol::UDP),
            )
            .expect("failed to create server socket");
        let server_fd = i32::try_from(server_fd).unwrap();
        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(TUN_IP_ADDR),
            SERVER_PORT,
        )));
        task.sys_bind(server_fd, server_addr.clone())
            .expect("failed to bind server");
        assert_eq!(
            server_addr,
            task.sys_getsockname(server_fd).expect("getsockname failed")
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
        let recv_ptr = crate::MutPtr::from_usize(recv_buf.as_mut_ptr() as usize);
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
                let fd = i32::try_from(ev.data).unwrap();
                assert_eq!(fd, server_fd);
            }
        }
        let n = task
            .sys_recvfrom(
                server_fd,
                recv_ptr,
                if test_trunc {
                    8 // intentionally small size to test truncation
                } else {
                    recv_buf.len()
                },
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
        let SocketAddress::Inet(sender_addr) = sender_addr.unwrap();
        assert_eq!(sender_addr.port(), CLIENT_PORT);

        task.sys_close(server_fd).expect("failed to close server");

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
        let task = init_platform(Some("tun99"));

        // Client socket and explicit bind
        let client_fd = task
            .sys_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::empty(),
                Some(litebox_common_linux::Protocol::UDP),
            )
            .expect("failed to create client socket");
        let client_fd = i32::try_from(client_fd).unwrap();

        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from([127, 0, 0, 1]),
            SERVER_PORT,
        )));

        // Send from client to server
        let msg = "Hello without connect()";
        let msg_ptr = ConstPtr::from_usize(msg.as_ptr().expose_provenance());
        task.sys_sendto(
            client_fd,
            msg_ptr,
            msg.len(),
            SendFlags::empty(),
            Some(server_addr.clone()),
        )
        .expect("failed to sendto");

        // Client implicitly bound to an ephemeral port via sendto
        let SocketAddress::Inet(client_addr) =
            task.sys_getsockname(client_fd).expect("getsockname failed");
        assert_ne!(client_addr.port(), 0);

        // Client connects to server address
        task.sys_connect(client_fd, server_addr.clone())
            .expect("failed to connect");

        // Now client can send without specifying addr
        let msg = "Hello with connect()";
        let msg_ptr = ConstPtr::from_usize(msg.as_ptr().expose_provenance());
        task.sys_sendto(client_fd, msg_ptr, msg.len(), SendFlags::empty(), None)
            .expect("failed to sendto");

        task.sys_close(client_fd).expect("failed to close client");
    }
}
