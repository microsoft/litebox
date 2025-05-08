use core::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicBool, AtomicU32},
};

use litebox::{
    fd::SocketFd,
    fs::OFlags,
    net::{Protocol, ReceiveFlags, SendFlags},
    platform::{RawConstPointer, RawMutPointer},
};
use litebox_common_linux::{AddressFamily, SockFlags, SockType, errno::Errno};

use crate::{ConstPtr, Descriptor, MutPtr, file_descriptors, litebox_net};

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
    pub(crate) fd: Option<SocketFd>,
    pub(crate) status: AtomicU32,
    pub(crate) close_on_exec: AtomicBool,
}

impl Drop for Socket {
    fn drop(&mut self) {
        if let Some(sockfd) = self.fd.take() {
            litebox_net().lock().close(sockfd);
        }
    }
}

impl Socket {
    pub(crate) fn new(fd: SocketFd, flags: SockFlags) -> Self {
        Self {
            fd: Some(fd),
            // SockFlags is a subset of OFlags
            status: AtomicU32::new(flags.bits()),
            close_on_exec: AtomicBool::new(flags.contains(SockFlags::CLOEXEC)),
        }
    }

    fn try_accept(&self) -> Result<SocketFd, Errno> {
        litebox_net()
            .lock()
            .accept(self.fd.as_ref().unwrap())
            .map_err(Errno::from)
    }

    fn accept(&self) -> Result<SocketFd, Errno> {
        if self.get_status().contains(OFlags::NONBLOCK) {
            self.try_accept()
        } else {
            // TODO: use `poll` instead of busy wait
            loop {
                match self.try_accept() {
                    Err(Errno::EAGAIN) => {}
                    ret => return ret,
                }
                core::hint::spin_loop();
            }
        }
    }

    fn bind(&self, sockaddr: SocketAddr) -> Result<(), Errno> {
        litebox_net()
            .lock()
            .bind(self.fd.as_ref().unwrap(), &sockaddr)
            .map_err(Errno::from)
    }

    fn connect(&self, sockaddr: SocketAddr) -> Result<(), Errno> {
        litebox_net()
            .lock()
            .connect(self.fd.as_ref().unwrap(), &sockaddr)
            .map_err(Errno::from)
    }

    fn listen(&self, backlog: u16) -> Result<(), Errno> {
        litebox_net()
            .lock()
            .listen(self.fd.as_ref().unwrap(), backlog)
            .map_err(Errno::from)
    }

    fn try_sendto(
        &self,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddr>,
    ) -> Result<usize, Errno> {
        let n = litebox_net()
            .lock()
            .send(self.fd.as_ref().unwrap(), buf, flags)?;
        if n == 0 { Err(Errno::EAGAIN) } else { Ok(n) }
    }

    fn sendto(
        &self,
        buf: &[u8],
        flags: SendFlags,
        sockaddr: Option<SocketAddr>,
    ) -> Result<usize, Errno> {
        if let Some(addr) = sockaddr {
            unimplemented!("sendto with addr {addr}");
        }
        if flags.contains(SendFlags::DONTWAIT) {
            self.try_sendto(buf, flags, sockaddr)
        } else {
            // TODO: use `poll` instead of busy wait
            loop {
                match self.try_sendto(buf, flags, sockaddr) {
                    Err(Errno::EAGAIN) => {}
                    ret => return ret,
                }
                core::hint::spin_loop();
            }
        }
    }

    fn try_receive(&self, buf: &mut [u8], flags: ReceiveFlags) -> Result<usize, Errno> {
        let n = litebox_net()
            .lock()
            .receive(self.fd.as_ref().unwrap(), buf, flags)?;
        if n == 0 { Err(Errno::EAGAIN) } else { Ok(n) }
    }

    fn receive(&self, buf: &mut [u8], flags: ReceiveFlags) -> Result<usize, Errno> {
        if flags.contains(ReceiveFlags::DONTWAIT) {
            self.try_receive(buf, flags)
        } else {
            // TODO: use `poll` instead of busy wait
            loop {
                match self.try_receive(buf, flags) {
                    Err(Errno::EAGAIN) => {}
                    ret => return ret,
                }
                core::hint::spin_loop();
            }
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
    let file = match domain {
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
            Descriptor::Socket(alloc::sync::Arc::new(Socket::new(socket, flags)))
        }
        AddressFamily::UNIX => todo!(),
        AddressFamily::INET6 | AddressFamily::NETLINK => return Err(Errno::EAFNOSUPPORT),
        _ => unimplemented!(),
    };
    Ok(file_descriptors().write().insert(file))
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

pub(crate) fn sys_accept(sockfd: i32) -> Result<u32, Errno> {
    let Ok(sockfd) = u32::try_from(sockfd) else {
        return Err(Errno::EBADF);
    };

    let file_table = file_descriptors().read();
    let socket = file_table.get_fd(sockfd).ok_or(Errno::EBADF)?;
    let file = match socket {
        Descriptor::Socket(socket) => {
            let socket = socket.clone();
            // drop file table as `accept` may block
            drop(file_table);
            let fd = socket.accept()?;
            Descriptor::Socket(alloc::sync::Arc::new(Socket::new(fd, SockFlags::empty())))
        }
        _ => return Err(Errno::ENOTSOCK),
    };
    Ok(file_descriptors().write().insert(file))
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

pub(crate) fn sys_sendto(
    fd: i32,
    buf: ConstPtr<u8>,
    len: usize,
    mut flags: SendFlags,
    sockaddr: Option<ConstPtr<u8>>,
    addrlen: Option<usize>,
) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };

    let sockaddr = sockaddr
        .map(|addr| read_sockaddr_from_user(addr, addrlen.unwrap_or(0)))
        .transpose()?;
    let buf = unsafe { buf.to_cow_slice(len).ok_or(Errno::EFAULT) }?;
    let file_table = file_descriptors().read();
    let socket = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
    match socket {
        Descriptor::Socket(socket) => {
            let socket = socket.clone();
            if socket.get_status().contains(OFlags::NONBLOCK) {
                flags.insert(SendFlags::DONTWAIT);
            }
            let sockaddr = match sockaddr {
                Some(SocketAddress::Inet(addr)) => Some(addr),
                None => None,
            };
            // drop file table as `sendto` may block
            drop(file_table);
            socket.sendto(&buf, flags, sockaddr)
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

pub(crate) fn sys_recvfrom(
    fd: i32,
    buf: MutPtr<u8>,
    len: usize,
    mut flags: ReceiveFlags,
    sockaddr: Option<ConstPtr<u8>>,
    addrlen: Option<usize>,
) -> Result<usize, Errno> {
    let Ok(fd) = u32::try_from(fd) else {
        return Err(Errno::EBADF);
    };
    if sockaddr.is_some() {
        unimplemented!();
    }

    let file_table = file_descriptors().read();
    let socket = file_table.get_fd(fd).ok_or(Errno::EBADF)?;
    match socket {
        Descriptor::Socket(socket) => {
            if socket.get_status().contains(OFlags::NONBLOCK) {
                flags.insert(ReceiveFlags::DONTWAIT);
            }
            // ignore MSG_WAITALL flag if MSG_DONTWAIT is set
            if flags.contains(ReceiveFlags::DONTWAIT) {
                flags.remove(ReceiveFlags::WAITALL);
            }
            let socket = socket.clone();
            // drop file table as `recvfrom` may block
            drop(file_table);
            let mut buffer: [u8; 4096] = [0; 4096];
            let size = socket.receive(&mut buffer, flags)?;
            buf.copy_from_slice(0, &buffer).ok_or(Errno::EFAULT);
            Ok(size)
        }
        _ => Err(Errno::ENOTSOCK),
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString as _;
    use litebox::net::{ReceiveFlags, SendFlags};
    use litebox_common_linux::{AddressFamily, SockFlags, SockType, errno::Errno};

    use crate::{ConstPtr, syscalls::net::sys_recvfrom};

    use super::{
        CSockInetAddr, CSockStorage, sys_accept, sys_bind, sys_connect, sys_listen, sys_sendto,
        sys_socket,
    };

    extern crate std;

    const TUN_IP_ADDR: [u8; 4] = [10, 0, 0, 2];

    fn create_inet_addr(addr: [u8; 4], port: u16) -> CSockStorage {
        let inetaddr = CSockInetAddr {
            family: AddressFamily::INET as i16,
            port: port.to_be(),
            addr,
            __pad: 0,
        };
        let mut sockaddr = CSockStorage::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                &inetaddr as *const _ as *const u8,
                &mut sockaddr as *mut _ as *mut u8,
                core::mem::size_of::<CSockInetAddr>(),
            );
        };
        sockaddr
    }

    fn test_tcp_socket(
        ip: [u8; 4],
        port: u16,
        is_nonblocking: bool,
        callback: impl FnOnce([u8; 4], u16) -> (),
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
        let sockaddr = create_inet_addr(ip, port);
        let addr: ConstPtr<u8> = unsafe { core::mem::transmute(&sockaddr) };
        sys_bind(server, addr, core::mem::size_of::<CSockInetAddr>())
            .expect("Failed to bind socket");
        sys_listen(server, 1).expect("Failed to listen on socket");

        // Invoke the callback after binding and listening
        callback(ip, port);

        let client_fd = if is_nonblocking {
            loop {
                match sys_accept(server) {
                    Ok(fd) => break fd,
                    Err(e) => {
                        assert_eq!(e, Errno::EAGAIN);
                        core::hint::spin_loop();
                    }
                }
            }
        } else {
            sys_accept(server).expect("Failed to accept connection")
        };
        let client_fd = i32::try_from(client_fd).unwrap();
        let buf = "Hello, world!";
        let ptr = unsafe { core::mem::transmute(buf.as_ptr()) };
        let n = if is_nonblocking {
            loop {
                match sys_sendto(client_fd, ptr, buf.len(), SendFlags::empty(), None, None) {
                    Ok(0) => {}
                    Err(e) => {
                        assert_eq!(e, Errno::EAGAIN);
                    }
                    Ok(n) => break n,
                }
                core::hint::spin_loop();
            }
        } else {
            sys_sendto(client_fd, ptr, buf.len(), SendFlags::empty(), None, None)
                .expect("Failed to send data")
        };
        assert_eq!(n, buf.len());
    }

    fn test_tcp_socket_with_internal_client_common(is_nonblocking: bool, port: u16) {
        crate::syscalls::tests::init_platform(Some("tun99"));

        test_tcp_socket(TUN_IP_ADDR, port, is_nonblocking, |ip, port| {
            std::thread::spawn(move || {
                let client = sys_socket(
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
                let client = i32::try_from(client).unwrap();
                let sockaddr = create_inet_addr(ip, port);
                let addr: ConstPtr<u8> = unsafe { core::mem::transmute(&sockaddr) };
                if is_nonblocking {
                    while let Err(e) =
                        sys_connect(client, addr, core::mem::size_of::<CSockInetAddr>())
                    {
                        assert_eq!(e, Errno::EAGAIN);
                        core::hint::spin_loop();
                    }
                } else {
                    sys_connect(client, addr, core::mem::size_of::<CSockInetAddr>())
                        .expect("Failed to connect to server");
                }

                let mut buf = [0u8; 24];
                let ptr = unsafe { core::mem::transmute(buf.as_mut_ptr()) };
                let n = if is_nonblocking {
                    loop {
                        match sys_recvfrom(
                            client,
                            ptr,
                            buf.len(),
                            ReceiveFlags::empty(),
                            None,
                            None,
                        ) {
                            Ok(0) => {}
                            Err(e) => {
                                assert_eq!(e, Errno::EAGAIN);
                            }
                            Ok(n) => break n,
                        }
                        core::hint::spin_loop();
                    }
                } else {
                    sys_recvfrom(client, ptr, buf.len(), ReceiveFlags::empty(), None, None)
                        .expect("Failed to receive data")
                };
                assert_eq!(&buf[..n], b"Hello, world!");
            });
        });
    }

    const EXTERNAL_CLIENT_C_CODE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
    // create a tcp client to connect to the server and receive message from it
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    int port;

    // get port number from command line argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }
    // convert port number from string to integer
    port = atoi(argv[1]);
    printf("Port number: %d\n", port);

    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // set server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("10.0.0.2");

    // sleep for 100ms to allow server to start
    usleep(100000);

    // connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    // receive message from server
    int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv");
        close(sockfd);
        return 1;
    }

    // null-terminate the received message
    buffer[bytes_received] = '\0';

    // print the received message
    printf("Received message: %s\n", buffer);

    // close the socket
    close(sockfd);
    return 0;
}
    "#;

    fn test_nonblocking_tcp_socket_with_external_client(port: u16) {
        let dir_path = std::env::var("OUT_DIR").unwrap();
        let src_path = std::path::Path::new(dir_path.as_str()).join("external_nb_client.c");
        std::fs::write(src_path.as_path(), EXTERNAL_CLIENT_C_CODE).unwrap();
        let output_path = std::path::Path::new(dir_path.as_str()).join("external_nb_client");
        crate::syscalls::tests::compile(
            src_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            true,
            false,
        );

        std::process::Command::new(output_path.to_str().unwrap())
            .args(&[port.to_string().as_str()])
            .spawn()
            .expect("Failed to spawn client");
        crate::syscalls::tests::init_platform(Some("tun99"));
        test_tcp_socket(TUN_IP_ADDR, port, true, |_, _| {});
    }

    #[test]
    fn test_tcp_socket_in_sequence() {
        test_tcp_socket_with_internal_client_common(true, 8080);
        test_tcp_socket_with_internal_client_common(false, 8081);
        test_nonblocking_tcp_socket_with_external_client(8082);
    }
}
