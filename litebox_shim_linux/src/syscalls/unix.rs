// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix domain sockets for the Linux shim layer.
//!
//! Each socket is a LiteBox [`unix_socket::UnixSocket`], so processes that share a socket through
//! inheritance see one socket. This module translates between Linux socket calls and LiteBox's
//! guest-neutral Unix socket operations.

use alloc::{
    string::{String, ToString as _},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::mem::{offset_of, size_of};
use litebox::{
    event::{Events, IOPollable, observer::Observer, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    process::ProcessError,
    unix_socket,
};
use litebox_broker_protocol::{
    ObjectHandle,
    fs::{FileMode as Mode, FileUser},
    socket::SocketType,
    unix_socket::{UNIX_SOCKET_BUFFER_SIZE, UnixSocketAddress, UnixSocketName},
};
use litebox_common_linux::{
    AddressFamily, IpOption, OFlags, ReceiveFlags, SendFlags, ShutdownHow, SockFlags, SockType,
    SocketOption, SocketOptionName, UnixProtocol, errno::Errno,
};

use crate::{
    GlobalState, ShimPlatform, Task, UserPtr, UserPtrMut,
    syscalls::{
        file::{linux_status_flags, status_flags_change},
        net::{ReceivePlan, open_flags, shutdown_mode},
    },
};

pub(crate) struct UnixSocketSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for UnixSocketSubsystem<Platform> {
    type Entry = UnixSocket<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for UnixSocket<Platform> {}

pub(crate) type UnixSocketFd<Platform> = TypedFd<UnixSocketSubsystem<Platform>>;

/// C-compatible structure for Unix socket addresses.
const UNIX_PATH_MAX: usize = 108;
#[repr(C)]
struct CSockUnixAddr {
    /// Address family (AF_UNIX)
    family: i16,
    /// Socket path or abstract address
    path: [u8; UNIX_PATH_MAX],
}

/// Reads the Unix socket address of `addrlen` bytes, at least its family, at `sockaddr`.
pub(super) fn read_sockaddr<Platform: ShimPlatform>(
    sockaddr: UserPtr<u8>,
    addrlen: usize,
) -> Result<UnixSocketAddr, Errno> {
    if addrlen > size_of::<CSockUnixAddr>() {
        return Err(Errno::EINVAL);
    }
    let path = sockaddr
        .to_owned_slice::<Platform>(addrlen)
        .ok_or(Errno::EFAULT)?;
    // skip the first two bytes (sa_family)
    let path = &path[offset_of!(CSockUnixAddr, path)..];
    if path.is_empty() {
        return Ok(UnixSocketAddr::Unnamed);
    }
    if path[0] == 0 {
        return Ok(UnixSocketAddr::Abstract(path[1..].to_vec()));
    }
    // Like Linux, accept a path without a NUL terminator (e.g., `addrlen = SUN_LEN(addr)`).
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    Ok(UnixSocketAddr::Path(
        String::from_utf8_lossy(&path[..end]).into_owned(),
    ))
}

/// Writes `addr`, truncated to `capacity` bytes, to `dst`, returning its full length.
pub(super) fn write_sockaddr<Platform: ShimPlatform>(
    addr: UnixSocketAddr,
    dst: UserPtrMut<u8>,
    capacity: usize,
) -> Result<usize, Errno> {
    // Like Linux, copy the full address truncated to the caller's buffer, which may be
    // too small even for the family.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(AddressFamily::UNIX as u16).to_ne_bytes());
    match addr {
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
    let copied = bytes.len().min(capacity);
    if copied != 0 {
        dst.write_slice_at_offset::<Platform>(0, &bytes[..copied])
            .ok_or(Errno::EFAULT)?;
    }
    Ok(bytes.len())
}

/// Represents a Unix socket address.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum UnixSocketAddr {
    /// Unnamed socket (not bound to any address)
    Unnamed,
    /// Filesystem path-based socket
    Path(String),
    /// Abstract namespace socket (not backed by filesystem)
    Abstract(Vec<u8>),
}

impl UnixSocketAddr {
    /// Returns the guest-neutral address naming `self`, resolving a relative path against the
    /// current working directory of `task`.
    ///
    /// Fails with `EINVAL` for an unnamed address, which names no socket.
    fn to_address<Platform: ShimPlatform>(
        &self,
        task: &Task<Platform>,
    ) -> Result<UnixSocketAddress, Errno> {
        match self {
            UnixSocketAddr::Unnamed => Err(Errno::EINVAL),
            UnixSocketAddr::Abstract(name) => Ok(UnixSocketAddress::Abstract(name.clone())),
            UnixSocketAddr::Path(path) => {
                let resolved = task.fs.borrow().context.read().resolve(path.as_str());
                Ok(UnixSocketAddress::Path {
                    path: resolved.to_string(),
                    name: path.as_bytes().to_vec(),
                })
            }
        }
    }
}

impl From<UnixSocketName> for UnixSocketAddr {
    fn from(name: UnixSocketName) -> Self {
        match name {
            UnixSocketName::Unnamed => UnixSocketAddr::Unnamed,
            UnixSocketName::Path(name) => {
                UnixSocketAddr::Path(String::from_utf8_lossy(&name).into_owned())
            }
            UnixSocketName::Abstract(name) => UnixSocketAddr::Abstract(name),
        }
    }
}

/// A Unix domain socket descriptor's open file description.
pub(crate) struct UnixSocket<Platform: ShimPlatform> {
    socket: Arc<unix_socket::UnixSocket<Platform>>,
}

impl<Platform: ShimPlatform> From<unix_socket::UnixSocket<Platform>> for UnixSocket<Platform> {
    fn from(socket: unix_socket::UnixSocket<Platform>) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

impl<Platform: ShimPlatform> UnixSocket<Platform> {
    /// Creates a socket of type `sock_type` for `protocol`, which must be zero.
    pub(super) fn new(
        litebox: &litebox::LiteBox<Platform>,
        sock_type: SockType,
        protocol: u8,
        flags: SockFlags,
    ) -> Result<Self, Errno> {
        let socket =
            litebox.create_unix_socket(socket_type(sock_type, protocol)?, open_flags(flags))?;
        Ok(socket.into())
    }

    /// Creates a pair of connected sockets of type `sock_type` for `protocol`, which must be
    /// zero.
    pub(super) fn new_connected_pair(
        litebox: &litebox::LiteBox<Platform>,
        sock_type: SockType,
        protocol: u8,
        flags: SockFlags,
    ) -> Result<(Self, Self), Errno> {
        let (first, second) = litebox
            .create_unix_socket_pair(socket_type(sock_type, protocol)?, open_flags(flags))?;
        Ok((first.into(), second.into()))
    }

    /// The LiteBox socket, which a child process inherits.
    pub(crate) fn unix_socket(&self) -> &Arc<unix_socket::UnixSocket<Platform>> {
        &self.socket
    }

    pub(super) fn is_stream(&self) -> bool {
        self.socket.socket_type() == SocketType::Stream
    }

    /// Plans a receive call, which receives once since Unix sockets don't support
    /// `MSG_WAITALL`.
    pub(super) fn receive_plan(&self) -> ReceivePlan {
        ReceivePlan {
            is_stream: self.is_stream(),
            wait_all: false,
            // LiteBox bounds each receive by the socket's receive timeout.
            timeout: None,
            copies_data: true,
        }
    }

    /// Binds the socket to `addr`, creating a filesystem node for a path with the permissions
    /// that the umask of `task` allows.
    pub(super) fn bind(&self, task: &Task<Platform>, addr: UnixSocketAddr) -> Result<(), Errno> {
        let address = addr.to_address(task)?;
        let mode = (Mode::RWXU | Mode::RWXG | Mode::RWXO) & !task.fs.borrow().umask();
        self.socket.bind(&address, acting_user(task), mode)?;
        Ok(())
    }

    pub(super) fn listen(&self, backlog: u16) -> Result<(), Errno> {
        self.socket.listen(u32::from(backlog))?;
        Ok(())
    }

    pub(super) fn connect(&self, task: &Task<Platform>, addr: UnixSocketAddr) -> Result<(), Errno> {
        let address = addr.to_address(task)?;
        self.socket
            .connect(&task.wait_cx(), &address, acting_user(task), false)?;
        Ok(())
    }

    /// Accepts a connection, storing the connecting socket's name in `peer` if requested.
    ///
    /// `flags` sets the status flags of the new socket only.
    pub(super) fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: SockFlags,
        peer: Option<&mut UnixSocketAddr>,
    ) -> Result<UnixSocket<Platform>, Errno> {
        let accepted = self.socket.accept(cx, open_flags(flags), false)?;
        if let Some(peer) = peer {
            *peer = accepted.name(true)?.into();
        }
        Ok(accepted.into())
    }

    pub(super) fn sendto(
        &self,
        task: &Task<Platform>,
        buf: &[u8],
        flags: SendFlags,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let supported_flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported sendto flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let address = addr.map(|addr| addr.to_address(task)).transpose()?;
        Ok(self.socket.send(
            &task.wait_cx(),
            address.as_ref(),
            buf,
            acting_user(task),
            flags.contains(SendFlags::DONTWAIT),
        )?)
    }

    /// Receives into `buf`, returning the length of the received data, which for a datagram
    /// socket may exceed `buf`.
    ///
    /// A datagram socket stores its sender's name in `source_addr` if requested.
    pub(super) fn recvfrom(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<usize, Errno> {
        let supported_flags = ReceiveFlags::DONTWAIT | ReceiveFlags::PEEK | ReceiveFlags::TRUNC;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvfrom flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let received = self.socket.receive(
            cx,
            buf,
            flags.contains(ReceiveFlags::PEEK),
            source_addr.is_some() && !self.is_stream(),
            flags.contains(ReceiveFlags::DONTWAIT),
        )?;
        if let (Some(source_addr), Some(source)) = (source_addr, received.source) {
            *source_addr = Some(source.into());
        }
        Ok(received.length)
    }

    pub(super) fn get_local_addr(&self) -> Result<UnixSocketAddr, Errno> {
        Ok(self.socket.name(false)?.into())
    }

    pub(super) fn get_peer_addr(&self) -> Result<UnixSocketAddr, Errno> {
        Ok(self.socket.name(true)?.into())
    }

    pub(super) fn setsockopt(
        &self,
        global: &GlobalState<Platform>,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        match global.setsockopt_common(optname, optval, optlen, |value| {
            Ok(self.socket.set_option(value)?)
        }) {
            Err(Errno::ENOPROTOOPT) => {} // continue to handle unix
            other => return other,
        }

        match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS => Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(so) => match so {
                // handled by `setsockopt_common`
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::KEEPALIVE
                | SocketOption::BROADCAST => {
                    unreachable!()
                }
                // Don't allow changing socket type and credentials
                SocketOption::TYPE | SocketOption::PEERCRED | SocketOption::ERROR => {
                    Err(Errno::ENOPROTOOPT)
                }
                // SO_RCVBUF / SO_SNDBUF are advisory hints. Accept them and keep
                // the fixed internal buffer size, instead of returning EOPNOTSUPP.
                // Log at debug so the accepted-but-ignored option stays visible.
                SocketOption::RCVBUF | SocketOption::SNDBUF => {
                    litebox_util_log::debug!(
                        "accepting and ignoring setsockopt(SO_RCVBUF/SO_SNDBUF) on unix socket; using fixed buffer size"
                    );
                    Ok(())
                }
            },
            SocketOptionName::TCP(_) => Err(Errno::EOPNOTSUPP),
        }
    }

    pub(super) fn getsockopt(
        &self,
        global: &GlobalState<Platform>,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        match global.getsockopt_common(optname, optval, len, |name| {
            Ok(self.socket.get_option(name)?)
        }) {
            Err(Errno::ENOPROTOOPT) => {} // continue to handle unix
            other => return other,
        }

        let val: u32 = match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS => return Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(so) => match so {
                // handled by `getsockopt_common`
                SocketOption::RCVTIMEO
                | SocketOption::SNDTIMEO
                | SocketOption::LINGER
                | SocketOption::REUSEADDR
                | SocketOption::KEEPALIVE
                | SocketOption::BROADCAST => {
                    unreachable!()
                }
                // Unix sockets don't track async errors
                SocketOption::ERROR => 0,
                SocketOption::TYPE => {
                    if self.is_stream() {
                        SockType::Stream as u32
                    } else {
                        SockType::Datagram as u32
                    }
                }
                SocketOption::RCVBUF | SocketOption::SNDBUF => UNIX_SOCKET_BUFFER_SIZE,
                SocketOption::PEERCRED => {
                    if !self.is_stream() {
                        log_unsupported!("get PEERCRED for unix datagram socket");
                        return Err(Errno::EOPNOTSUPP);
                    }
                    if self.socket.name(true).is_ok() {
                        log_unsupported!("get PEERCRED for unix socket");
                        return Err(Errno::EOPNOTSUPP);
                    }
                    let ucred = litebox_common_linux::Ucred {
                        pid: 0,
                        uid: u32::MAX,
                        gid: u32::MAX,
                    };
                    return super::write_to_user::<_, Platform>(ucred, optval, len);
                }
            },
            SocketOptionName::TCP(_) => return Err(Errno::EOPNOTSUPP),
        };
        super::write_to_user::<_, Platform>(val, optval, len)
    }

    pub(super) fn shutdown(&self, how: ShutdownHow) -> Result<(), Errno> {
        self.socket.shutdown(shutdown_mode(how))?;
        Ok(())
    }

    /// Returns the `F_GETFL` flags of the socket, which every descriptor sharing it sees.
    pub(super) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.socket.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the socket to their values in `flags`, ignoring
    /// flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(super) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.socket.set_status_flags(mask, flags)?;
        Ok(())
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Runs `f` on the Unix socket at `fd`, without holding the descriptor table.
    pub(super) fn with_unix_socket<R>(
        &self,
        fd: &UnixSocketFd<Platform>,
        f: impl FnOnce(&UnixSocket<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts a Unix socket of type `socket_type` this process inherited from
    /// its parent as `handle`.
    pub(super) fn adopt_inherited_unix_socket(
        &self,
        handle: ObjectHandle,
        socket_type: SocketType,
    ) -> Result<UnixSocketFd<Platform>, ProcessError> {
        let socket = self
            .litebox
            .adopt_inherited_unix_socket(handle, socket_type)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<UnixSocketSubsystem<Platform>>(UnixSocket::from(socket)))
    }
}

impl<Platform: ShimPlatform> IOPollable for UnixSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.socket.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.socket.check_io_events()
    }
}

/// The socket type of a Unix socket of type `sock_type` for `protocol`.
fn socket_type(sock_type: SockType, protocol: u8) -> Result<SocketType, Errno> {
    UnixProtocol::try_from(protocol).map_err(|_| Errno::EPROTONOSUPPORT)?;
    match sock_type {
        SockType::Stream => Ok(SocketType::Stream),
        SockType::Datagram => Ok(SocketType::Datagram),
        e => {
            log_unsupported!("Unsupported unix socket type: {:?}", e);
            Err(Errno::ESOCKTNOSUPPORT)
        }
    }
}

fn acting_user<Platform: ShimPlatform>(task: &Task<Platform>) -> FileUser {
    task.fs.borrow().context.read().acting_user()
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    type TestTask = crate::Task<crate::syscalls::tests::TestPlatform>;

    use alloc::{string::ToString, vec::Vec};
    use litebox::event::Events;
    use litebox_common_linux::{
        AddressFamily, AtFlags, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption,
        SocketOptionName, TimeParam, errno::Errno,
    };

    use super::UnixSocketAddr;
    use crate::{
        UserPtr, UserPtrMut,
        syscalls::{
            net::{SocketAddress, read_sockaddr_from_user},
            tests::init_platform,
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
