use core::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicBool, AtomicU32},
};

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
    pub fn to_sockaddr(self, addrlen: usize) -> Result<SocketAddress, Errno> {
        let family = self.sa_family as u32;
        match family {
            litebox_common_linux::AF_UNIX => todo!(),
            litebox_common_linux::AF_INET => {
                if addrlen < size_of::<CSockInetAddr>() {
                    return Err(Errno::EINVAL);
                }
                let inet_addr = self.transmute_to_inet();
                Ok(SocketAddress::Inet(SocketAddr::V4(SocketAddrV4::from(
                    inet_addr,
                ))))
            }
            _ => {
                todo!("unsupported family {family}");
            }
        }
    }
}

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

const UNIX_PATH_MAX: usize = 108;
#[repr(C)]
struct CSockUnixAddr {
    family: i16,
    path: [u8; UNIX_PATH_MAX],
}

pub(super) enum SocketAddress {
    Inet(SocketAddr),
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

    fn accept(&self) -> Result<SocketFd, Errno> {
        litebox_net().lock().accept(&self.fd).map_err(Errno::from)
    }

    fn bind(&self, sockaddr: SocketAddr) -> Result<(), Errno> {
        litebox_net()
            .lock()
            .bind(&self.fd, &sockaddr)
            .map_err(Errno::from)
    }

    fn connect(&self, sockaddr: SocketAddr) -> Result<(), Errno> {
        litebox_net()
            .lock()
            .connect(&self.fd, &sockaddr)
            .map_err(Errno::from)
    }

    fn listen(&self, backlog: u16) -> Result<(), Errno> {
        litebox_net()
            .lock()
            .listen(&self.fd, backlog)
            .map_err(Errno::from)
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

fn read_sockaddr_from_user(sockaddr: ConstPtr<u8>, addrlen: usize) -> Result<SocketAddress, Errno> {
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

pub(crate) fn sys_accept(sockfd: i32) -> Result<SocketFd, Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => socket.accept(),
        _ => Err(Errno::ENOTSOCK),
    }
}

pub(crate) fn sys_connect(fd: i32, sockaddr: ConstPtr<u8>, addrlen: usize) -> Result<(), Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    let addr = read_sockaddr_from_user(sockaddr, addrlen)?;
    match file_descriptors().read().get_fd(fd).ok_or(Errno::EBADF)? {
        Descriptor::Socket(socket) => {
            let SocketAddress::Inet(addr) = addr;
            socket.connect(addr)
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

pub(crate) fn sys_bind(sockfd: i32, sockaddr: ConstPtr<u8>, addrlen: usize) -> Result<(), Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    let addr = read_sockaddr_from_user(sockaddr, addrlen)?;
    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => {
            let SocketAddress::Inet(addr) = addr;
            socket.bind(addr)
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

pub(crate) fn sys_listen(sockfd: i32, backlog: u16) -> Result<(), Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    match file_descriptors()
        .read()
        .get_fd(sockfd)
        .ok_or(Errno::EBADF)?
    {
        Descriptor::Socket(socket) => socket.listen(backlog),
        _ => Err(Errno::ENOTSOCK),
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::{AddressFamily, SockFlags, SockType, errno::Errno};

    use crate::ConstPtr;

    use super::{
        CSockInetAddr, CSockStorage, sys_accept, sys_bind, sys_connect, sys_listen, sys_socket,
    };

    extern crate std;

    #[test]
    fn test_blocking_inet_socket() {
        crate::syscalls::tests::init_platform(Some("tun99"));

        let server = sys_socket(
            AddressFamily::INET,
            SockType::Stream,
            SockFlags::empty(),
            None,
        )
        .unwrap();
        let server = i32::try_from(server).unwrap();
        let inetaddr = CSockInetAddr {
            family: AddressFamily::INET as i16,
            port: 8080u16.to_be(),
            addr: [10, 0, 0, 2],
            __pad: 0,
        };
        let mut sockaddr = CSockStorage::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                &inetaddr as *const _ as *const u8,
                &mut sockaddr as *mut _ as *mut u8,
                core::mem::size_of::<CSockInetAddr>(),
            );
        }
        let addr: ConstPtr<u8> = unsafe { core::mem::transmute(&sockaddr) };
        sys_bind(server, addr, core::mem::size_of::<CSockInetAddr>())
            .expect("Failed to bind socket");
        sys_listen(server, 1).expect("Failed to listen on socket");

        std::thread::spawn(move || {
            let client = sys_socket(
                AddressFamily::INET,
                SockType::Stream,
                SockFlags::empty(),
                None,
            )
            .unwrap();
            let client = i32::try_from(client).unwrap();
            let addr: ConstPtr<u8> = unsafe { core::mem::transmute(&sockaddr) };
            while let Err(e) = sys_connect(client, addr, core::mem::size_of::<CSockInetAddr>()) {
                assert_eq!(e, Errno::EAGAIN);
                core::hint::spin_loop();
            }

            loop {
                {
                    core::hint::spin_loop();
                }
            }
        });

        while let Err(e) = sys_accept(server) {
            assert_eq!(e, Errno::EAGAIN);
            core::hint::spin_loop();
        }
    }
}
