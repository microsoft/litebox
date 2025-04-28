use core::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, AtomicU32},
};

use alloc::string::ToString as _;
use litebox::{fd::SocketFd, net::Protocol, platform::RawConstPointer};
use litebox_common_linux::{AddressFamily, SockFlags, SockType, errno::Errno};

use crate::{ConstPtr, Descriptor, file_descriptors, litebox_net};

const ADDR_MAX_LEN: usize = 128;

#[repr(C)]
struct CSockStorage {
    pub sa_family: u16,
    pub bytes: [u8; ADDR_MAX_LEN - 2],
}

impl Default for CSockStorage {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

macro_rules! transmute_sockaddr {
    ($func_name:ident, $addr_type:ty) => {
        impl CSockStorage {
            /// Transmute the CSockStorage to a specific type
            pub fn $func_name(self) -> $addr_type {
                let mut buf = [0u8; size_of::<$addr_type>()];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        &self as *const _ as *const u8,
                        buf.as_mut_ptr(),
                        size_of::<$addr_type>(),
                    );
                    core::mem::transmute(buf)
                }
            }
        }
    };
}

transmute_sockaddr!(transmute_to_unix, CSockUnixAddr);
transmute_sockaddr!(transmute_to_inet, CSockInetAddr);

impl CSockStorage {
    pub fn to_sockaddr(self, addrlen: usize) -> Result<SocketAddr, Errno> {
        let family = self.sa_family as u32;
        match family {
            litebox_common_linux::AF_UNIX => todo!(),
            litebox_common_linux::AF_INET => {
                if addrlen < size_of::<CSockInetAddr>() {
                    return Err(Errno::EINVAL);
                }
                let inet_addr = self.transmute_to_inet();
                Ok(SocketAddr::IPv4(SocketIPv4Addr::from(inet_addr)))
            }
            _ => {
                todo!("unsupported family");
            }
        }
    }
}

#[repr(C, packed)]
pub struct CSockInetAddr {
    pub family: i16,
    pub port: u16,
    pub addr: [u8; 4],
    pub padding: u64,
}

struct SocketIPv4Addr {
    pub addr: Ipv4Addr,
    pub port: u16,
}

impl From<CSockInetAddr> for SocketIPv4Addr {
    fn from(c_addr: CSockInetAddr) -> Self {
        Self {
            addr: Ipv4Addr::from(c_addr.addr),
            port: u16::from_be(c_addr.port),
        }
    }
}

const UNIX_PATH_MAX: usize = 108;
#[repr(C)]
struct CSockUnixAddr {
    pub family: i16,
    pub path: [u8; UNIX_PATH_MAX],
}

pub(super) enum SocketAddr {
    IPv4(SocketIPv4Addr),
}

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

fn read_sockaddr_from_user(sockaddr: ConstPtr<u8>, addrlen: usize) -> Result<SocketAddr, Errno> {
    if addrlen < 2 {
        return Err(Errno::EINVAL);
    }

    let mut storage = CSockStorage::default();
    let data = unsafe { sockaddr.to_cow_slice(core::cmp::min(addrlen, size_of::<CSockStorage>())) }
        .ok_or(Errno::EFAULT)?;
    unsafe {
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            core::ptr::from_mut(&mut storage).cast(),
            data.len(),
        );
    }

    storage.to_sockaddr(addrlen)
}

pub(crate) fn sys_connect(fd: i32, sockaddr: ConstPtr<u8>, addrlen: usize) -> Result<(), Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    let addr = read_sockaddr_from_user(sockaddr, addrlen)?;
    match file_descriptors().read().get_fd(fd).ok_or(Errno::EBADF)? {
        Descriptor::Socket(socket) => todo!(),
        _ => Err(Errno::ENOTSOCK),
    }
}
