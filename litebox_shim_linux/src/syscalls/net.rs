use core::sync::atomic::{AtomicBool, AtomicU32};

use litebox::{fd::SocketFd, net::Protocol};
use litebox_common_linux::{AddressFamily, SockFlags, SockType, errno::Errno};

use crate::{Descriptor, file_descriptors, litebox_net};

pub(crate) struct Socket {
    pub(crate) fd: SocketFd,
    pub(crate) status: AtomicU32,
    pub(crate) close_on_exec: AtomicBool,
}

impl Socket {
    pub(crate) fn new(fd: SocketFd, flags: SockFlags) -> Self {
        Self {
            fd,
            // SockFlags is a subset of OFlags
            status: AtomicU32::new(flags.bits()),
            close_on_exec: AtomicBool::new(flags.contains(SockFlags::CLOEXEC)),
        }
    }
    crate::syscalls::common_functions_for_file_status!();
}

pub(crate) fn sys_socket(
    domain: AddressFamily,
    ty: SockType,
    flags: SockFlags,
    protocol: Option<Protocol>,
) -> Result<u32, Errno> {
    match domain {
        AddressFamily::INET => {
            let protocol = match ty {
                SockType::Stream => {
                    if protocol.is_some_and(|p| p != Protocol::Tcp) {
                        return Err(Errno::EINVAL);
                    }
                    Protocol::Tcp
                }
                SockType::Datagram => {
                    if protocol.is_some_and(|p| p != Protocol::Udp) {
                        return Err(Errno::EINVAL);
                    }
                    Protocol::Udp
                }
                SockType::Raw => protocol.unwrap_or(Protocol::Raw { protocol: 0 }),
                _ => unimplemented!(),
            };
            let socket = litebox_net().lock().socket(protocol)?;
            Ok(file_descriptors()
                .write()
                .insert(Descriptor::Socket(Socket::new(socket, flags))))
        }
        AddressFamily::UNIX => todo!(),
        AddressFamily::INET6 | AddressFamily::NETLINK => Err(Errno::EAFNOSUPPORT),
        _ => unimplemented!(),
    }
}
