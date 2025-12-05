//! Socket-related syscalls, e.g., socket, bind, listen, etc.

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use alloc::sync::Arc;
use litebox::{
    event::{
        Events,
        polling::TryOpError,
        wait::{WaitContext, WaitError},
    },
    fs::OFlags,
    net::{CloseBehavior, TcpOptionData, errors::AcceptError},
    platform::{RawConstPointer as _, RawMutPointer as _},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    AddressFamily, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption, SocketOptionName,
    TcpOption, errno::Errno,
};

use crate::Platform;
use crate::{ConstPtr, Descriptor, MutPtr};
use crate::{GlobalState, Task};

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

/// Socket-related implementation. Currently these methods are on `GlobalState`
/// so that they can access `net` and the litebox descriptor table. This might
/// change if the nature of the litebox descriptor table changes, or if network
/// namespaces are implemented.
impl GlobalState {
    fn initialize_socket(&self, fd: &SocketFd, sock_type: SockType, flags: SockFlags) {
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
    }

    fn with_socket_options<R>(&self, fd: &SocketFd, f: impl FnOnce(&SocketOptions) -> R) -> R {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |opt| f(opt))
            .unwrap()
    }
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

    fn setsockopt(
        &self,
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
                        self.with_socket_options_mut(fd, |opt| {
                            opt.recv_timeout = duration;
                        });
                        return Ok(());
                    }
                    SocketOption::SNDTIMEO => {
                        let duration = read_timeval_as_duration(optval)?;
                        self.with_socket_options_mut(fd, |opt| {
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
                        let timeout = if linger.onoff != 0 {
                            Some(core::time::Duration::from_secs(u64::from(linger.linger)))
                        } else {
                            None
                        };
                        self.with_socket_options_mut(fd, |opt| {
                            opt.linger_timeout = timeout;
                        });
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
                        self.with_socket_options_mut(fd, |opt| {
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
                        if let Err(err) = self.net.lock().set_tcp_option(
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
                                    unimplemented!(
                                        "SO_KEEPALIVE is not supported for non-TCP sockets"
                                    )
                                }
                                _ => unimplemented!(),
                            }
                        }
                        self.with_socket_options_mut(fd, |opt| {
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
                match to {
                    TcpOption::CONGESTION => {
                        const TCP_CONGESTION_NAME_MAX: usize = 16;
                        let data =
                            unsafe { optval.to_cow_slice(TCP_CONGESTION_NAME_MAX.min(optlen)) }
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
                        Ok(())
                    }
                    TcpOption::KEEPCNT | TcpOption::KEEPIDLE | TcpOption::INFO => {
                        Err(Errno::EOPNOTSUPP)
                    }
                    _ => {
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
                                self.net
                                    .lock()
                                    .set_tcp_option(fd, litebox::net::TcpOptionData::NODELAY(on))?;
                                Ok(())
                            }
                            TcpOption::KEEPINTVL => {
                                const MAX_TCP_KEEPINTVL: u32 = 32767;
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
                                Ok(())
                            }
                            // handled above
                            TcpOption::KEEPCNT
                            | TcpOption::KEEPIDLE
                            | TcpOption::INFO
                            | TcpOption::CONGESTION => {
                                unreachable!()
                            }
                        }
                    }
                }
            }
        }
    }

    fn getsockopt(
        &self,
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
                        let tv = self
                            .with_socket_options(fd, |options| match sopt {
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
                            SocketOption::TYPE => self.get_socket_type(fd)? as u32,
                            SocketOption::REUSEADDR => {
                                u32::from(self.with_socket_options(fd, |o| o.reuse_address))
                            }
                            SocketOption::BROADCAST => 1, // TODO: We don't support disabling SO_BROADCAST
                            SocketOption::KEEPALIVE => {
                                u32::from(self.with_socket_options(fd, |o| o.keep_alive))
                            }
                            SocketOption::RCVBUF | SocketOption::SNDBUF => {
                                litebox::net::SOCKET_BUFFER_SIZE.truncate()
                            }
                            SocketOption::PEERCRED => return Err(Errno::ENOPROTOOPT),
                            SocketOption::RCVTIMEO
                            | SocketOption::SNDTIMEO
                            | SocketOption::LINGER => {
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
                        unsafe { optval.write_slice_at_offset(0, &name.as_bytes()[..len]) }
                            .ok_or(Errno::EFAULT)?;
                        len
                    }
                    TcpOption::KEEPCNT | TcpOption::KEEPIDLE | TcpOption::INFO => {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    _ => {
                        let val: u32 = match tcpopt {
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
                            // handled above
                            TcpOption::KEEPCNT
                            | TcpOption::KEEPIDLE
                            | TcpOption::INFO
                            | TcpOption::CONGESTION => {
                                unreachable!()
                            }
                        };
                        let data = &val.to_ne_bytes()[..size_of::<u32>().min(len as usize)];
                        unsafe { optval.write_slice_at_offset(0, data) }.ok_or(Errno::EFAULT)?;
                        size_of::<u32>()
                    }
                }
            }
        };
        unsafe { optlen.write_at_offset(0, new_len.truncate()) }.ok_or(Errno::EFAULT)?;
        Ok(())
    }

    fn register_observer(
        &self,
        fd: &SocketFd,
        observer: alloc::sync::Weak<dyn litebox::event::observer::Observer<Events>>,
        mask: Events,
    ) -> Result<(), Errno> {
        self.net
            .lock()
            .with_iopollable(fd, |poll| poll.register_observer(observer, mask))
            .ok_or(Errno::EBADF)
    }

    fn try_accept(
        &self,
        fd: &SocketFd,
        peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd, TryOpError<Errno>> {
        self.net.lock().accept(fd, peer).map_err(|e| match e {
            AcceptError::NoConnectionsReady => TryOpError::TryAgain,
            AcceptError::InvalidFd | AcceptError::NotListening => TryOpError::Other(e.into()),
            _ => unimplemented!(),
        })
    }

    fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd,
        mut peer: Option<&mut SocketAddr>,
    ) -> Result<SocketFd, Errno> {
        cx.wait_on_events(
            self.get_status(fd).contains(OFlags::NONBLOCK),
            Events::IN,
            |observer, filter| self.register_observer(fd, observer, filter),
            || self.try_accept(fd, peer.as_deref_mut()),
        )
        .map_err(Errno::from)
    }

    fn bind(&self, fd: &SocketFd, sockaddr: SocketAddr) -> Result<(), Errno> {
        self.net.lock().bind(fd, &sockaddr).map_err(Errno::from)
    }

    fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd,
        sockaddr: SocketAddr,
    ) -> Result<(), Errno> {
        let mut check_progress = false;
        cx.wait_on_events(
            self.get_status(fd).contains(OFlags::NONBLOCK),
            Events::IN | Events::OUT,
            |observer, filter| self.register_observer(fd, observer, filter),
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

    fn listen(&self, fd: &SocketFd, backlog: u16) -> Result<(), Errno> {
        self.net.lock().listen(fd, backlog).map_err(Errno::from)
    }

    fn try_sendto(
        &self,
        fd: &SocketFd,
        buf: &[u8],
        flags: litebox::net::SendFlags,
        sockaddr: Option<SocketAddr>,
    ) -> Result<usize, TryOpError<Errno>> {
        match self.net.lock().send(fd, buf, flags, sockaddr) {
            Ok(0) => Err(TryOpError::TryAgain),
            Ok(n) => Ok(n),
            Err(e) => Err(TryOpError::Other(e.into())),
        }
    }

    pub(crate) fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &SocketFd,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddr>,
    ) -> Result<usize, Errno> {
        // Convert `SendFlags` to `litebox::net::SendFlags`
        // Note [`Network::send`] is non-blocking and `DONTWAIT` is handled below
        // so we don't convert `DONTWAIT` here.
        // Also, `NOSIGNAL` is handled after the send.
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
        let ret = cx
            .with_timeout(timeout)
            .wait_on_events(
                self.get_status(fd).contains(OFlags::NONBLOCK)
                    || flags.contains(SendFlags::DONTWAIT),
                Events::OUT,
                |observer, filter| self.register_observer(fd, observer, filter),
                || self.try_sendto(fd, buf, new_flags, sockaddr),
            )
            .map_err(Errno::from);
        if let Err(Errno::EPIPE) = ret
            && !flags.contains(SendFlags::NOSIGNAL)
        {
            unimplemented!("send signal SIGPIPE on EPIPE");
        }
        ret
    }

    fn try_receive(
        &self,
        fd: &SocketFd,
        buf: &mut [u8],
        flags: litebox::net::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, TryOpError<Errno>> {
        match self.net.lock().receive(fd, buf, flags, source_addr) {
            Ok(0) => Err(TryOpError::TryAgain),
            Ok(n) => Ok(n),
            Err(e) => Err(TryOpError::Other(e.into())),
        }
    }

    pub(crate) fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
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

        let timeout = self.with_socket_options(fd, |opt| opt.recv_timeout);
        cx.with_timeout(timeout)
            .wait_on_events(
                self.get_status(fd).contains(OFlags::NONBLOCK)
                    || flags.contains(ReceiveFlags::DONTWAIT),
                Events::IN,
                |observer, filter| self.register_observer(fd, observer, filter),
                || self.try_receive(fd, buf, new_flags, source_addr.as_deref_mut()),
            )
            .map_err(Errno::from)
    }

    fn get_socket_type(&self, fd: &SocketFd) -> Result<SockType, Errno> {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |sock_type: &SockType| *sock_type)
            .map_err(|e| match e {
                litebox::fd::MetadataError::NoSuchMetadata => Errno::ENOTSOCK,
                litebox::fd::MetadataError::ClosedFd => Errno::EBADF,
            })
    }

    fn get_status(&self, fd: &SocketFd) -> litebox::fs::OFlags {
        self.litebox
            .descriptor_table()
            .with_metadata(fd, |SocketOFlags(flags)| *flags)
            .unwrap()
            & litebox::fs::OFlags::STATUS_FLAGS_MASK
    }

    pub(crate) fn close_socket(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: Arc<SocketFd>,
    ) -> Result<(), Errno> {
        let linger_timeout = self.with_socket_options(&fd, |opt| opt.linger_timeout);
        let behavior = match linger_timeout {
            Some(timeout) if timeout.is_zero() => CloseBehavior::Immediate,
            Some(_) => CloseBehavior::GracefulIfNoPendingData,
            None => CloseBehavior::Graceful,
        };
        match cx.with_timeout(linger_timeout).wait_on_events(
            self.get_status(&fd).contains(OFlags::NONBLOCK),
            Events::HUP,
            |observer, filter| self.register_observer(&fd, observer, filter),
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
            Err(e) => Err(e.into()),
        }
    }
}

impl Task {
    /// Handle syscall `socket`
    pub(crate) fn sys_socket(
        &self,
        domain: u32,
        type_and_flags: u32,
        protocol: u8,
    ) -> Result<usize, Errno> {
        let ty = type_and_flags & 0x0f;
        let flags = type_and_flags & !0x0f;
        let domain = AddressFamily::try_from(domain).map_err(|_| {
            log_unsupported!("socket(domain = {domain})");
            Errno::EINVAL
        })?;
        let ty = SockType::try_from(ty).map_err(|_| {
            log_unsupported!("socket(type = {ty})");
            Errno::EINVAL
        })?;
        let flags = SockFlags::from_bits_truncate(flags);
        let protocol = if protocol == 0 {
            None
        } else {
            Some(
                litebox_common_linux::Protocol::try_from(protocol).map_err(|_| {
                    log_unsupported!("socket(protocol = {protocol})");
                    Errno::EINVAL
                })?,
            )
        };
        self.do_socket(domain, ty, flags, protocol)
            .map(|fd| fd as usize)
    }
    fn do_socket(
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
                let socket = self.global.net.lock().socket(protocol)?;
                self.global.initialize_socket(&socket, ty, flags);
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
        addr: Option<MutPtr<u8>>,
        addrlen: Option<MutPtr<u32>>,
        flags: SockFlags,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let mut remote_addr = addr.is_some().then(SocketAddress::default);
        let fd = self.do_accept(sockfd, remote_addr.as_mut(), flags)?;
        if let (Some(addr), Some(remote_addr)) = (addr, remote_addr) {
            let addrlen = addrlen.ok_or(Errno::EFAULT)?;
            if let Err(err) = write_sockaddr_to_user(remote_addr, addr, addrlen) {
                // If we fail to write the address back to user, we need to close the accepted socket.
                self.sys_close(i32::try_from(fd).unwrap())
                    .expect("close a newly-accepted socket failed");
                return Err(err);
            }
        }
        Ok(fd as usize)
    }
    fn do_accept(
        &self,
        sockfd: u32,
        peer: Option<&mut SocketAddress>,
        flags: SockFlags,
    ) -> Result<u32, Errno> {
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let socket = file_table.get_fd(sockfd).ok_or(Errno::EBADF)?;
        let file = match socket {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                files.with_socket_fd(*raw_fd, |fd| {
                    drop(file_table); // Drop before possibly-blocking `accept`
                    let sock_type = self.global.get_socket_type(fd)?;
                    let mut socket_addr = peer
                        .is_some()
                        .then(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
                    let accepted_fd =
                        self.global
                            .accept(&self.wait_cx(), fd, socket_addr.as_mut())?;
                    if let (Some(peer), Some(socket_addr)) = (peer, socket_addr) {
                        *peer = SocketAddress::Inet(socket_addr);
                    }

                    self.global
                        .initialize_socket(&accepted_fd, sock_type, flags);
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
    pub(crate) fn sys_connect(
        &self,
        fd: i32,
        sockaddr: ConstPtr<u8>,
        addrlen: usize,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = read_sockaddr_from_user(sockaddr, addrlen)?;
        self.do_connect(fd, sockaddr).map(|()| 0)
    }
    fn do_connect(&self, fd: u32, sockaddr: SocketAddress) -> Result<(), Errno> {
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        match file_table.get_fd(fd).ok_or(Errno::EBADF)? {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                let SocketAddress::Inet(addr) = sockaddr;
                drop(file_table); // Drop before possibly-blocking `connect`
                self.global.connect(&self.wait_cx(), fd, addr)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `bind`
    pub(crate) fn sys_bind(
        &self,
        sockfd: i32,
        sockaddr: ConstPtr<u8>,
        addrlen: usize,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = read_sockaddr_from_user(sockaddr, addrlen)?;
        self.do_bind(sockfd, sockaddr).map(|()| 0)
    }
    fn do_bind(&self, sockfd: u32, sockaddr: SocketAddress) -> Result<(), Errno> {
        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                let SocketAddress::Inet(addr) = sockaddr;
                self.global.bind(fd, addr)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `listen`
    pub(crate) fn sys_listen(&self, sockfd: i32, backlog: u16) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        self.do_listen(sockfd, backlog).map(|()| 0)
    }
    fn do_listen(&self, sockfd: u32, backlog: u16) -> Result<(), Errno> {
        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => {
                files.with_socket_fd(*raw_fd, |fd| self.global.listen(fd, backlog))
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
        addr: Option<ConstPtr<u8>>,
        addrlen: u32,
    ) -> Result<usize, Errno> {
        let Ok(fd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = addr
            .map(|addr| read_sockaddr_from_user(addr, addrlen as usize))
            .transpose()?;
        self.do_sendto(fd, buf, len, flags, sockaddr)
    }
    fn do_sendto(
        &self,
        fd: u32,
        buf: ConstPtr<u8>,
        len: usize,
        flags: SendFlags,
        sockaddr: Option<SocketAddress>,
    ) -> Result<usize, Errno> {
        let buf = unsafe { buf.to_cow_slice(len).ok_or(Errno::EFAULT) }?;
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let socket = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match socket {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                let sockaddr = sockaddr.map(|SocketAddress::Inet(addr)| addr);
                drop(file_table); // Drop before possibly-blocking `sendto`
                self.global
                    .sendto(&self.wait_cx(), fd, &buf, flags, sockaddr)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
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
        let msg = unsafe { msg.read_at_offset(0) }.ok_or(Errno::EFAULT)?;
        self.do_sendmsg(fd, &msg, flags)
    }
    fn do_sendmsg(
        &self,
        fd: u32,
        msg: &litebox_common_linux::UserMsgHdr<Platform>,
        flags: SendFlags,
    ) -> Result<usize, Errno> {
        let sock_addr = if msg.msg_name.as_usize() != 0 {
            Some(read_sockaddr_from_user(
                msg.msg_name,
                msg.msg_namelen as usize,
            )?)
        } else {
            None
        };
        if msg.msg_controllen != 0 {
            unimplemented!("ancillary data is not supported");
        }
        if msg.msg_iovlen == 0 || msg.msg_iovlen > 1024 {
            return Err(Errno::EINVAL);
        }
        let iovs = unsafe { msg.msg_iov.to_cow_slice(msg.msg_iovlen) }.ok_or(Errno::EFAULT)?;
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        let socket = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
        match socket {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |socket| {
                // drop file table as `sendto` may block
                drop(file_table);
                let sock_addr = sock_addr.map(|SocketAddress::Inet(addr)| addr);
                let mut total_sent = 0;
                for iov in iovs.iter() {
                    if iov.iov_len == 0 {
                        continue;
                    }
                    let buf =
                        unsafe { iov.iov_base.to_cow_slice(iov.iov_len) }.ok_or(Errno::EFAULT)?;
                    total_sent +=
                        self.global
                            .sendto(&self.wait_cx(), socket, &buf, flags, sock_addr)?;
                }
                Ok(total_sent)
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
        addr: Option<MutPtr<u8>>,
        addrlen: MutPtr<u32>,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(fd) else {
            return Err(Errno::EBADF);
        };
        let mut source_addr = None;
        let size = self.do_recvfrom(
            sockfd,
            buf,
            len,
            flags,
            if addr.is_some() {
                Some(&mut source_addr)
            } else {
                None
            },
        )?;
        if let Some(src_addr) = source_addr
            && let Some(sock_ptr) = addr
        {
            write_sockaddr_to_user(src_addr, sock_ptr, addrlen)?;
        }
        Ok(size)
    }
    fn do_recvfrom(
        &self,
        sockfd: u32,
        buf: MutPtr<u8>,
        len: usize,
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddress>>,
    ) -> Result<usize, Errno> {
        let files = self.files.borrow();
        let file_table = files.file_descriptors.read();
        match file_table.get_fd(sockfd).ok_or(Errno::EBADF)? {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                const MAX_LEN: usize = 4096;
                let mut buffer: [u8; MAX_LEN] = [0; MAX_LEN];
                let buffer: &mut [u8] = &mut buffer[..MAX_LEN.min(len)];
                let mut addr = None;
                drop(file_table); // Drop before possibly-blocking `receive`
                let size = self.global.receive(
                    &self.wait_cx(),
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
        level: u32,
        optname: u32,
        optval: ConstPtr<u8>,
        optlen: usize,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            log_unsupported!("setsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        })?;
        self.do_setsockopt(sockfd, optname, optval, optlen)
            .map(|()| 0)
    }
    fn do_setsockopt(
        &self,
        sockfd: u32,
        optname: SocketOptionName,
        optval: ConstPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                self.global.setsockopt(fd, optname, optval, optlen)
            }),
            _ => Err(Errno::ENOTSOCK),
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
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let optname = SocketOptionName::try_from(level, optname).ok_or_else(|| {
            log_unsupported!("setsockopt(level = {level}, optname = {optname})");
            Errno::EINVAL
        })?;
        self.do_getsockopt(sockfd, optname, optval, optlen)
            .map(|()| 0)
    }
    fn do_getsockopt(
        &self,
        sockfd: u32,
        optname: SocketOptionName,
        optval: MutPtr<u8>,
        optlen: MutPtr<u32>,
    ) -> Result<(), Errno> {
        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                self.global.getsockopt(fd, optname, optval, optlen)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `getsockname`
    pub(crate) fn sys_getsockname(
        &self,
        sockfd: i32,
        addr: MutPtr<u8>,
        addrlen: MutPtr<u32>,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = self.do_getsockname(sockfd)?;
        write_sockaddr_to_user(sockaddr, addr, addrlen).map(|()| 0)
    }
    fn do_getsockname(&self, sockfd: u32) -> Result<SocketAddress, Errno> {
        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                self.global
                    .net
                    .lock()
                    .get_local_addr(fd)
                    .map(SocketAddress::Inet)
                    .map_err(Errno::from)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }

    /// Handle syscall `getpeername`
    pub(crate) fn sys_getpeername(
        &self,
        sockfd: i32,
        addr: MutPtr<u8>,
        addrlen: MutPtr<u32>,
    ) -> Result<usize, Errno> {
        let Ok(sockfd) = u32::try_from(sockfd) else {
            return Err(Errno::EBADF);
        };
        let sockaddr = self.do_getpeername(sockfd)?;
        write_sockaddr_to_user(sockaddr, addr, addrlen).map(|()| 0)
    }
    fn do_getpeername(&self, sockfd: u32) -> Result<SocketAddress, Errno> {
        let files = self.files.borrow();
        match files
            .file_descriptors
            .read()
            .get_fd(sockfd)
            .ok_or(Errno::EBADF)?
        {
            Descriptor::LiteBoxRawFd(raw_fd) => files.with_socket_fd(*raw_fd, |fd| {
                self.global
                    .net
                    .lock()
                    .get_remote_addr(fd)
                    .map(SocketAddress::Inet)
                    .map_err(Errno::from)
            }),
            _ => Err(Errno::ENOTSOCK),
        }
    }
}

#[cfg(target_arch = "x86")]
impl Task {
    pub(crate) fn sys_socketcall(&self, call: i32, args: ConstPtr<usize>) -> Result<usize, Errno> {
        use litebox_common_linux::SocketcallType;
        macro_rules! parse_socketcall_args {
            ($nargs:literal => $func:ident { $($field:ident: $tt:tt),* $(,)? }) => {{
                let args = unsafe { args.to_cow_slice($nargs) }.ok_or(Errno::EFAULT)?;
                self.$func (
                    $(parse_socketcall_args!(@convert args $tt )),*
                )
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
    use crate::{ConstPtr, MutPtr};

    extern crate alloc;
    extern crate std;

    const TUN_IP_ADDR: [u8; 4] = [10, 0, 0, 2];
    const TUN_IP_ADDR_STR: &str = "10.0.0.2";
    const SERVER_PORT: u16 = 8080;
    const CLIENT_PORT: u16 = 8081;

    fn init_platform(tun_device_name: Option<&str>) -> crate::Task {
        let task = crate::syscalls::tests::init_platform(tun_device_name);
        let global = task.global.clone();
        // Start a background thread to perform network interaction
        // Naive implementation for testing purpose only
        std::thread::spawn(move || {
            loop {
                while global
                    .net
                    .lock()
                    .perform_platform_interaction()
                    .call_again_immediately()
                {}
                core::hint::spin_loop();
            }
        });
        task
    }

    fn close_socket(task: &crate::Task, fd: u32) {
        task.sys_close(i32::try_from(fd).unwrap())
            .expect("close socket failed");
    }

    fn epoll_add(task: &crate::Task, epfd: i32, target_fd: u32, events: litebox::event::Events) {
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
        task: &crate::Task,
        epfd: i32,
        events: &mut [litebox_common_linux::EpollEvent],
    ) -> usize {
        let events_ptr = crate::MutPtr::from_usize(events.as_mut_ptr() as usize);
        task.sys_epoll_pwait(epfd, events_ptr, events.len().truncate(), -1, None, 0)
            .expect("epoll_wait failed")
    }

    fn test_tcp_socket_as_server(
        task: &crate::Task,
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
                None,
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
                let ptr = ConstPtr::from_usize(buf.as_ptr().expose_provenance());
                let n = task
                    .do_sendto(client_fd, ptr, buf.len(), SendFlags::empty(), None)
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
                let hdr = litebox_common_linux::UserMsgHdr {
                    msg_name: ConstPtr::from_usize(0),
                    msg_namelen: 0,
                    msg_iov: ConstPtr::from_usize(iovec.as_ptr() as usize),
                    msg_iovlen: iovec.len(),
                    msg_control: ConstPtr::from_usize(0),
                    msg_controllen: 0,
                    msg_flags: SendFlags::empty(),
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
                    assert_eq!(n, 1);
                    for ev in &events[..n] {
                        assert!(ev.events & litebox::event::Events::IN.bits() != 0);
                        let fd = u32::try_from(ev.data).unwrap();
                        assert_eq!(fd, client_fd);
                    }
                }
                let mut recv_buf = [0u8; 48];
                let recv_ptr = crate::MutPtr::from_usize(recv_buf.as_mut_ptr() as usize);
                let n = task
                    .do_recvfrom(
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

        close_socket(task, client_fd);
        close_socket(task, server);
    }

    fn test_tcp_socket_with_external_client(
        port: u16,
        is_nonblocking: bool,
        test_trunc: bool,
        option: &'static str,
    ) {
        let task = init_platform(Some("tun99"));
        test_tcp_socket_as_server(&task, TUN_IP_ADDR, port, is_nonblocking, test_trunc, option);
    }

    fn test_tcp_socket_send(is_nonblocking: bool, test_trunc: bool) {
        let task = init_platform(Some("tun99"));
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
        let task = init_platform(Some("tun99"));
        let socket_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Stream,
                SockFlags::empty(),
                None,
            )
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
    }

    #[test]
    fn test_tun_tcp_socket_as_client() {
        let task = init_platform(Some("tun99"));

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
            .do_socket(
                AddressFamily::INET,
                SockType::Stream,
                SockFlags::empty(),
                None,
            )
            .expect("failed to create client socket");

        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from([10, 0, 0, 1]),
            SERVER_PORT,
        )));
        task.do_connect(client_fd, server_addr)
            .expect("failed to connect to server");

        let buf = "Hello, world!";
        let ptr = ConstPtr::from_usize(buf.as_ptr().expose_provenance());
        let len = buf.len();
        let n = task
            .do_sendto(client_fd, ptr, len, SendFlags::empty(), None)
            .unwrap();
        assert_eq!(n, len);

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

    fn blocking_udp_server_socket(test_trunc: bool, is_nonblocking: bool) {
        let task = init_platform(Some("tun99"));

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
                Some(litebox_common_linux::Protocol::UDP),
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
                let fd = u32::try_from(ev.data).unwrap();
                assert_eq!(fd, server_fd);
            }
        }
        let n = task
            .do_recvfrom(
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
        let task = init_platform(Some("tun99"));

        // Client socket and explicit bind
        let client_fd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Datagram,
                SockFlags::empty(),
                Some(litebox_common_linux::Protocol::UDP),
            )
            .expect("failed to create client socket");

        let server_addr = SocketAddress::Inet(SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::from([127, 0, 0, 1]),
            SERVER_PORT,
        )));

        // Send from client to server
        let msg = "Hello without connect()";
        let msg_ptr = ConstPtr::from_usize(msg.as_ptr().expose_provenance());
        task.do_sendto(
            client_fd,
            msg_ptr,
            msg.len(),
            SendFlags::empty(),
            Some(server_addr.clone()),
        )
        .expect("failed to sendto");

        // Client implicitly bound to an ephemeral port via sendto
        let SocketAddress::Inet(client_addr) =
            task.do_getsockname(client_fd).expect("getsockname failed");
        assert_ne!(client_addr.port(), 0);

        // Client connects to server address
        task.do_connect(client_fd, server_addr.clone())
            .expect("failed to connect");

        // Now client can send without specifying addr
        let msg = "Hello with connect()";
        let msg_ptr = ConstPtr::from_usize(msg.as_ptr().expose_provenance());
        task.do_sendto(client_fd, msg_ptr, msg.len(), SendFlags::empty(), None)
            .expect("failed to sendto");

        close_socket(&task, client_fd);
    }

    #[test]
    fn test_tun_tcp_sockopt() {
        let task = init_platform(Some("tun99"));
        let sockfd = task
            .do_socket(
                AddressFamily::INET,
                SockType::Stream,
                SockFlags::empty(),
                None,
            )
            .expect("failed to create socket");

        let mut congestion_name = [0u8; 16];
        let mut optlen: u32 = congestion_name.len().truncate();
        task.do_getsockopt(
            sockfd,
            SocketOptionName::TCP(TcpOption::CONGESTION),
            MutPtr::from_usize(congestion_name.as_mut_ptr() as usize),
            MutPtr::from_usize(&raw mut optlen as usize),
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
    }

    #[test]
    fn test_socket_dup_and_close() {
        let task = init_platform(None);
        let socket_fd = task
            .do_socket(
                litebox_common_linux::AddressFamily::INET,
                litebox_common_linux::SockType::Stream,
                litebox_common_linux::SockFlags::empty(),
                None,
            )
            .unwrap();
        let socket_fd2 = task
            .sys_dup(i32::try_from(socket_fd).unwrap(), None, None)
            .unwrap();
        close_socket(&task, socket_fd);
        close_socket(&task, socket_fd2);
    }
}
