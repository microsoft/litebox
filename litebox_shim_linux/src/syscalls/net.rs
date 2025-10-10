//! Socket-related syscalls, e.g., socket, bind, listen, etc.

/// XXX(jayb): How do we handle things like `sys_accept` without holding a lock on the file
/// descriptor.  See #120.
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use alloc::sync::Arc;
use litebox::{
    fs::OFlags,
    net::{SocketFd, TcpOptionData},
    platform::{RawConstPointer as _, RawMutPointer as _},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption, SocketOptionName,
    TcpOption, errno::Errno,
};

use crate::{ConstPtr, Descriptor, MutPtr, file_descriptors, litebox_net};
use crate::{Platform, litebox};

const ADDR_MAX_LEN: usize = 128;

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

#[repr(C)]
struct CSockStorage {
    sa_family: u16,
    bytes: [u8; ADDR_MAX_LEN - 2],
}

impl Default for CSockStorage {
    fn default() -> Self {
        Self {
            sa_family: 0,
            bytes: [0u8; _],
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
#[derive(Clone)]
pub(crate) enum SocketAddress {
    Inet(SocketAddr),
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

fn get_socket_fd(raw_fd: usize) -> Result<Arc<SocketFd<Platform>>, Errno> {
    match crate::raw_descriptor_store()
        .read()
        .fd_from_raw_integer(raw_fd)
    {
        Ok(fd) => Ok(fd),
        Err(litebox::fd::ErrRawIntFd::NotFound | litebox::fd::ErrRawIntFd::InvalidSubsystem) => {
            Err(Errno::EBADF)
        }
    }
}

fn get_socket_type(raw_fd: usize) -> Result<SockType, Errno> {
    let fd = get_socket_fd(raw_fd)?;
    crate::litebox()
        .descriptor_table()
        .with_metadata(&fd, |sock_type: &SockType| *sock_type)
        .map_err(|e| match e {
            litebox::fd::MetadataError::NoSuchMetadata => Errno::ENOTSOCK,
            litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
        })
}

struct SocketOFlags(OFlags);

fn initialize_socket(raw_fd: usize, sock_type: SockType, flags: SockFlags) {
    let mut status = OFlags::RDWR;
    status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));

    let fd = get_socket_fd(raw_fd).unwrap();
    let mut dt = litebox().descriptor_table_mut();
    let old = dt.set_entry_metadata(&fd, SocketOptions::default());
    assert!(old.is_none());
    if flags.contains(SockFlags::CLOEXEC) {
        let old = dt.set_fd_metadata(&fd, litebox_common_linux::FileDescriptorFlags::FD_CLOEXEC);
        assert!(old.is_none());
    }
    let old = dt.set_fd_metadata(&fd, sock_type);
    assert!(old.is_none());
    let old = dt.set_entry_metadata(&fd, SocketOFlags(status));
    assert!(old.is_none());
}

fn with_socket_options<R>(raw_fd: usize, f: impl FnOnce(&SocketOptions) -> R) -> Result<R, Errno> {
    let fd = get_socket_fd(raw_fd)?;
    Ok(litebox()
        .descriptor_table()
        .with_metadata(&fd, |opt| f(opt))
        .unwrap())
}
fn with_socket_options_mut<R>(
    raw_fd: usize,
    f: impl FnOnce(&mut SocketOptions) -> R,
) -> Result<R, Errno> {
    let fd = get_socket_fd(raw_fd)?;
    Ok(litebox()
        .descriptor_table_mut()
        .with_metadata_mut(&fd, |opt| f(opt))
        .unwrap())
}

fn setsockopt(
    raw_fd: usize,
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
                    with_socket_options_mut(raw_fd, |opt| opt.recv_timeout = duration)?;
                    return Ok(());
                }
                SocketOption::SNDTIMEO => {
                    let duration = read_timeval_as_duration(optval)?;
                    with_socket_options_mut(raw_fd, |opt| opt.send_timeout = duration)?;
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
                    with_socket_options_mut(raw_fd, |opt| opt.reuse_address = val != 0)?;
                }
                SocketOption::BROADCAST => {
                    if val == 0 {
                        todo!("disable SO_BROADCAST");
                    }
                }
                SocketOption::KEEPALIVE => {
                    let keep_alive = val != 0;
                    let fd = get_socket_fd(raw_fd)?;
                    if let Err(err) = litebox_net().lock().set_tcp_option(
                        &fd,
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
                    with_socket_options_mut(raw_fd, |opt| opt.keep_alive = keep_alive)?;
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
                    let fd = get_socket_fd(raw_fd)?;
                    if let Err(err) = litebox_net()
                        .lock()
                        .set_tcp_option(&fd, litebox::net::TcpOptionData::NODELAY(on))
                    {
                        match err {
                            litebox::net::errors::SetTcpOptionError::InvalidFd => {
                                return Err(Errno::EBADF);
                            }
                            litebox::net::errors::SetTcpOptionError::NotTcpSocket => {
                                return Err(Errno::EOPNOTSUPP);
                            }
                            _ => unimplemented!(),
                        }
                    }
                    Ok(())
                }
                _ => unimplemented!("TCP option {to:?}"),
            }
        }
    }
}

fn getsockopt(
    raw_fd: usize,
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
                    let tv = with_socket_options(raw_fd, |options| match sopt {
                        SocketOption::RCVTIMEO => options.recv_timeout,
                        SocketOption::SNDTIMEO => options.send_timeout,
                        SocketOption::LINGER => options.linger_timeout,
                        _ => unreachable!(),
                    })?
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
                        SocketOption::TYPE => get_socket_type(raw_fd)? as u32,
                        SocketOption::REUSEADDR => {
                            u32::from(with_socket_options(raw_fd, |o| o.reuse_address)?)
                        }
                        SocketOption::BROADCAST => 1, // TODO: We don't support disabling SO_BROADCAST
                        SocketOption::KEEPALIVE => {
                            u32::from(with_socket_options(raw_fd, |o| o.keep_alive)?)
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
                    let fd = get_socket_fd(raw_fd)?;
                    let TcpOptionData::KEEPALIVE(interval) = litebox_net()
                        .lock()
                        .get_tcp_option(&fd, litebox::net::TcpOptionName::KEEPALIVE)?
                    else {
                        unreachable!()
                    };
                    interval.map_or(0, |d| d.as_secs().try_into().unwrap())
                }
                TcpOption::NODELAY | TcpOption::CORK => {
                    let fd = get_socket_fd(raw_fd)?;
                    let TcpOptionData::NODELAY(nodelay) = litebox_net()
                        .lock()
                        .get_tcp_option(&fd, litebox::net::TcpOptionName::NODELAY)?
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

fn try_accept(raw_fd: usize) -> Result<SocketFd<Platform>, Errno> {
    let fd = get_socket_fd(raw_fd)?;
    litebox_net().lock().accept(&fd).map_err(Errno::from)
}

fn accept(raw_fd: usize) -> Result<SocketFd<Platform>, Errno> {
    if get_status(raw_fd).contains(OFlags::NONBLOCK) {
        try_accept(raw_fd)
    } else {
        // TODO: use `poll` instead of busy wait
        loop {
            match try_accept(raw_fd) {
                Err(Errno::EAGAIN) => {}
                ret => return ret,
            }
            core::hint::spin_loop();
        }
    }
}

fn bind(raw_fd: usize, sockaddr: SocketAddr) -> Result<(), Errno> {
    let fd = get_socket_fd(raw_fd)?;
    litebox_net()
        .lock()
        .bind(&fd, &sockaddr)
        .map_err(Errno::from)
}

fn connect(raw_fd: usize, sockaddr: SocketAddr) -> Result<(), Errno> {
    let fd = get_socket_fd(raw_fd)?;
    litebox_net()
        .lock()
        .connect(&fd, &sockaddr)
        .map_err(Errno::from)
}

fn listen(raw_fd: usize, backlog: u16) -> Result<(), Errno> {
    let fd = get_socket_fd(raw_fd)?;
    litebox_net()
        .lock()
        .listen(&fd, backlog)
        .map_err(Errno::from)
}

fn try_sendto(
    raw_fd: usize,
    buf: &[u8],
    flags: litebox::net::SendFlags,
    sockaddr: Option<SocketAddr>,
) -> Result<usize, Errno> {
    let fd = get_socket_fd(raw_fd)?;
    let n = litebox_net().lock().send(&fd, buf, flags, sockaddr)?;
    if n == 0 { Err(Errno::EAGAIN) } else { Ok(n) }
}

pub(crate) fn sendto(
    raw_fd: usize,
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

    if get_status(raw_fd).contains(OFlags::NONBLOCK) || flags.contains(SendFlags::DONTWAIT) {
        try_sendto(raw_fd, buf, new_flags, sockaddr)
    } else {
        let timeout = with_socket_options(raw_fd, |opt| opt.send_timeout)?;
        if timeout.is_some() {
            todo!("send timeout");
        }

        // TODO: use `poll` instead of busy wait
        loop {
            match try_sendto(raw_fd, buf, new_flags, sockaddr) {
                Err(Errno::EAGAIN) => {}
                ret => return ret,
            }
            core::hint::spin_loop();
        }
    }
}

fn try_receive(
    raw_fd: usize,
    buf: &mut [u8],
    flags: litebox::net::ReceiveFlags,
    source_addr: Option<&mut Option<SocketAddr>>,
) -> Result<usize, Errno> {
    let fd = get_socket_fd(raw_fd)?;
    let n = litebox_net().lock().receive(&fd, buf, flags, source_addr)?;
    if n == 0 { Err(Errno::EAGAIN) } else { Ok(n) }
}

pub(crate) fn receive(
    raw_fd: usize,
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
        match get_socket_type(raw_fd)? {
            SockType::Datagram | SockType::Raw => {
                new_flags.insert(litebox::net::ReceiveFlags::TRUNC);
            }
            SockType::Stream => {
                new_flags.insert(litebox::net::ReceiveFlags::DISCARD);
            }
            _ => unimplemented!(),
        }
    }

    if get_status(raw_fd).contains(OFlags::NONBLOCK) || flags.contains(ReceiveFlags::DONTWAIT) {
        try_receive(raw_fd, buf, new_flags, source_addr)
    } else {
        let timeout = with_socket_options(raw_fd, |opt| opt.recv_timeout)?;
        if timeout.is_some() {
            todo!("recv timeout");
        }

        // TODO: use `poll` instead of busy wait
        loop {
            match try_receive(raw_fd, buf, new_flags, source_addr.as_deref_mut()) {
                Err(Errno::EAGAIN) => {}
                ret => return ret,
            }
            core::hint::spin_loop();
        }
    }
}

fn get_status(raw_fd: usize) -> litebox::fs::OFlags {
    let fd = get_socket_fd(raw_fd).unwrap();
    litebox()
        .descriptor_table()
        .with_metadata(&fd, |SocketOFlags(flags)| *flags)
        .unwrap()
        & litebox::fs::OFlags::STATUS_FLAGS_MASK
}

fn set_status(raw_fd: usize, flag: litebox::fs::OFlags, on: bool) {
    let fd = get_socket_fd(raw_fd).unwrap();
    litebox()
        .descriptor_table_mut()
        .with_metadata_mut(&fd, |SocketOFlags(flags)| flags.set(flag, on))
        .unwrap();
}

/// Handle syscall `socket`
pub(crate) fn sys_socket(
    domain: AddressFamily,
    ty: SockType,
    flags: SockFlags,
    protocol: Option<litebox_common_linux::Protocol>,
) -> Result<u32, Errno> {
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
            let mut rds = crate::raw_descriptor_store().write();
            let raw_fd = rds.fd_into_raw_integer(socket);
            drop(rds);
            initialize_socket(raw_fd, ty, flags);
            Descriptor::Socket(raw_fd)
        }
        AddressFamily::UNIX => todo!(),
        AddressFamily::INET6 | AddressFamily::NETLINK => return Err(Errno::EAFNOSUPPORT),
        _ => unimplemented!(),
    };
    file_descriptors().write().insert(file).map_err(|desc| {
        crate::syscalls::file::do_close(desc).expect("closing descriptor should succeed");
        Errno::EMFILE
    })
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

/// Handle syscall `accept`
pub(crate) fn sys_accept(
    sockfd: i32,
    addr: Option<MutPtr<u8>>,
    addrlen: Option<MutPtr<u32>>,
    flags: SockFlags,
) -> Result<u32, Errno> {
    if addr.is_some() || addrlen.is_some() {
        todo!("accept with addr");
    }

    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    let file_table = file_descriptors().read();
    let socket = file_table.get_fd(sockfd).ok_or(Errno::EBADF)?;
    let file = match socket {
        Descriptor::Socket(socket) => {
            let socket = *socket;
            // drop file table as `accept` may block
            drop(file_table);
            let fd = accept(socket)?;
            let mut rds = crate::raw_descriptor_store().write();
            let raw_fd = rds.fd_into_raw_integer(fd);
            drop(rds);
            let sock_type = get_socket_type(socket)?;
            initialize_socket(raw_fd, sock_type, flags);
            Descriptor::Socket(raw_fd)
        }
        _ => return Err(Errno::ENOTSOCK),
    };
    file_descriptors().write().insert(file).map_err(|desc| {
        crate::syscalls::file::do_close(desc).expect("closing descriptor should succeed");
        Errno::EMFILE
    })
}

/// Handle syscall `connect`
pub(crate) fn sys_connect(fd: i32, sockaddr: SocketAddress) -> Result<(), Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors().read().get_fd(fd).ok_or(Errno::EBADF)? {
        Descriptor::Socket(socket) => {
            let SocketAddress::Inet(addr) = sockaddr;
            connect(*socket, addr)
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

/// Handle syscall `bind`
pub(crate) fn sys_bind(sockfd: i32, sockaddr: SocketAddress) -> Result<(), Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => {
            let SocketAddress::Inet(addr) = sockaddr;
            bind(*socket, addr)
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

/// Handle syscall `listen`
pub(crate) fn sys_listen(sockfd: i32, backlog: u16) -> Result<(), Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => listen(*socket, backlog),
        _ => Err(Errno::ENOTSOCK),
    }
}

/// Handle syscall `sendto`
pub(crate) fn sys_sendto(
    fd: i32,
    buf: ConstPtr<u8>,
    len: usize,
    mut flags: SendFlags,
    sockaddr: Option<SocketAddress>,
) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    let buf = unsafe { buf.to_cow_slice(len).ok_or(Errno::EFAULT) }?;
    let file_table = file_descriptors().read();
    let socket = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
    match socket {
        Descriptor::Socket(socket) => {
            let socket = *socket;
            // drop file table as `sendto` may block
            drop(file_table);
            sendto(
                socket,
                &buf,
                flags,
                sockaddr.map(|SocketAddress::Inet(addr)| addr),
            )
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

/// Handle syscall `recvfrom`
pub(crate) fn sys_recvfrom(
    fd: i32,
    buf: MutPtr<u8>,
    len: usize,
    mut flags: ReceiveFlags,
    source_addr: Option<&mut Option<SocketAddress>>,
) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    let file_table = file_descriptors().read();
    let socket = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
    match socket {
        Descriptor::Socket(socket) => {
            let socket = *socket;
            // drop file table as `receive` may block
            drop(file_table);
            let mut buffer: [u8; 4096] = [0; 4096];
            let mut addr = None;
            let size = receive(
                socket,
                &mut buffer,
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
            buf.copy_from_slice(0, &buffer[..size])
                .ok_or(Errno::EFAULT)?;
            Ok(size)
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

pub(crate) fn sys_setsockopt(
    sockfd: i32,
    optname: SocketOptionName,
    optval: ConstPtr<u8>,
    optlen: usize,
) -> Result<(), Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => setsockopt(*socket, optname, optval, optlen),
        _ => Err(Errno::ENOTSOCK),
    }
}

/// Handle syscall `getsockopt`
pub(crate) fn sys_getsockopt(
    sockfd: i32,
    optname: SocketOptionName,
    optval: MutPtr<u8>,
    optlen: MutPtr<u32>,
) -> Result<(), Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => getsockopt(*socket, optname, optval, optlen),
        _ => Err(Errno::ENOTSOCK),
    }
}

/// Handle syscall `getsockname`
pub(crate) fn sys_getsockname(sockfd: i32) -> Result<SocketAddr, Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => litebox_net()
            .lock()
            .get_local_addr(&*get_socket_fd(*socket)?)
            .map_err(Errno::from),
        _ => Err(Errno::ENOTSOCK),
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use alloc::string::ToString as _;
    use litebox::platform::RawConstPointer as _;
    use litebox_common_linux::{
        AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType, errno::Errno,
    };

    use super::{SocketAddress, sys_connect, sys_getsockname};
    use crate::{
        ConstPtr,
        syscalls::{file::sys_close, net::sys_recvfrom},
    };

    use super::{sys_accept, sys_bind, sys_listen, sys_sendto, sys_socket};

    extern crate alloc;
    extern crate std;

    const TUN_IP_ADDR: [u8; 4] = [10, 0, 0, 2];
    const TUN_IP_ADDR_STR: &str = "10.0.0.2";
    const SERVER_PORT: u16 = 8080;
    const CLIENT_PORT: u16 = 8081;

    fn test_tcp_socket(
        ip: [u8; 4],
        port: u16,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &str,
    ) {
        let server = sys_socket(
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
        let sockaddr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(ip),
            port,
        )));
        sys_bind(server, sockaddr).expect("Failed to bind socket");
        sys_listen(server, 1).expect("Failed to listen on socket");

        let buf = "Hello, world!";
        let mut child = match option {
            "sendto" => std::process::Command::new("nc")
                .args([
                    "-w", // timeout for connects and final net reads
                    "1",
                    TUN_IP_ADDR_STR,
                    SERVER_PORT.to_string().as_str(),
                ])
                .stdout(std::process::Stdio::piped())
                .spawn(),
            "recvfrom" => std::process::Command::new("sh")
                .args([
                    "-c",
                    &alloc::format!("echo -n '{buf}' | nc -w 1 {TUN_IP_ADDR_STR} {SERVER_PORT}",),
                ])
                .spawn(),
            _ => panic!("Unknown option"),
        }
        .expect("failed to run nc");

        let client_fd = if is_nonblocking {
            loop {
                match sys_accept(server, None, None, SockFlags::empty()) {
                    Ok(fd) => break fd,
                    Err(e) => {
                        assert_eq!(e, Errno::EAGAIN);
                        core::hint::spin_loop();
                    }
                }
            }
        } else {
            sys_accept(server, None, None, SockFlags::empty()).expect("Failed to accept connection")
        };
        let client_fd = i32::try_from(client_fd).unwrap();
        match option {
            "sendto" => {
                let ptr = ConstPtr::from_usize(buf.as_ptr().expose_provenance());
                let n = sys_sendto(client_fd, ptr, buf.len(), SendFlags::empty(), None)
                    .expect("Failed to send data");
                assert_eq!(n, buf.len());
                let output = child.wait_with_output().expect("Failed to wait for client");
                let stdout = alloc::string::String::from_utf8_lossy(&output.stdout);
                assert_eq!(stdout, buf);
            }
            "recvfrom" => {
                if is_nonblocking {
                    unimplemented!("non-blocking recvfrom")
                }
                let mut recv_buf = [0u8; 48];
                let recv_ptr = crate::MutPtr::from_usize(recv_buf.as_mut_ptr() as usize);
                let n = sys_recvfrom(
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
                let _ = child.wait().expect("Failed to wait for client");
            }
            _ => panic!("Unknown option"),
        }

        sys_close(client_fd).expect("Failed to close client socket");
        sys_close(server).expect("Failed to close server socket");
    }

    fn test_tcp_socket_with_external_client(
        port: u16,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &str,
    ) {
        crate::syscalls::tests::init_platform(Some("tun99"));
        test_tcp_socket(TUN_IP_ADDR, port, is_nonblocking, test_trunc, option);
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
    fn test_tun_blocking_recvfrom_tcp_socket_with_truncation() {
        test_tcp_socket_with_external_client(SERVER_PORT, false, true, "recvfrom");
    }

    fn blocking_udp_server_socket(test_trunc: bool) {
        crate::syscalls::tests::init_platform(Some("tun99"));

        // Server socket and bind
        let server_fd = sys_socket(
            AddressFamily::INET,
            SockType::Datagram,
            SockFlags::empty(),
            Some(litebox_common_linux::Protocol::UDP),
        )
        .expect("failed to create server socket");
        let server_fd = i32::try_from(server_fd).unwrap();
        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from(TUN_IP_ADDR),
            SERVER_PORT,
        )));
        sys_bind(server_fd, server_addr.clone()).expect("failed to bind server");

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
        let n = sys_recvfrom(
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

        sys_close(server_fd).expect("failed to close server");

        child.wait().expect("Failed to wait for client");
    }

    #[test]
    fn test_tun_blocking_udp_server_socket() {
        blocking_udp_server_socket(false);
    }

    #[test]
    fn test_tun_blocking_udp_server_socket_with_truncation() {
        blocking_udp_server_socket(true);
    }

    #[test]
    fn test_tun_udp_client_socket_without_server() {
        // We do not support loopback yet, so this test only checks that
        // the client can send packets without a server.
        crate::syscalls::tests::init_platform(Some("tun99"));

        // Client socket and explicit bind
        let client_fd = sys_socket(
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
        sys_sendto(
            client_fd,
            msg_ptr,
            msg.len(),
            SendFlags::empty(),
            Some(server_addr.clone()),
        )
        .expect("failed to sendto");

        // Client implicitly bound to an ephemeral port via sendto
        let client_addr = sys_getsockname(client_fd).expect("getsockname failed");
        assert_ne!(client_addr.port(), 0);

        // Client connects to server address
        sys_connect(client_fd, server_addr.clone()).expect("failed to connect");

        // Now client can send without specifying addr
        let msg = "Hello with connect()";
        let msg_ptr = ConstPtr::from_usize(msg.as_ptr().expose_provenance());
        sys_sendto(client_fd, msg_ptr, msg.len(), SendFlags::empty(), None)
            .expect("failed to sendto");

        sys_close(client_fd).expect("failed to close client");
    }
}
