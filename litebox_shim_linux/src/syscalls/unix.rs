// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix domain sockets for the Linux shim layer.
//!
//! Each socket is a broker-owned [`LocalSocket`], so processes that share a socket through
//! inheritance see one socket. This module translates between Linux socket calls and the
//! broker's guest-neutral local socket operations.

use alloc::{
    string::{String, ToString as _},
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    event::{Events, IOPollable, observer::Observer, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    local_sockets::LocalSocket,
    process::ProcessError,
};
use litebox_broker_protocol::{
    ObjectHandle,
    fs::{FileMode as Mode, FileOpenFlags, FileUser},
    local_socket::{
        LOCAL_SOCKET_BUFFER_SIZE, LocalSocketAddress, LocalSocketName, LocalSocketOption,
    },
    socket::{ShutdownMode, SocketType},
};
use litebox_common_linux::{
    IpOption, OFlags, ReceiveFlags, SendFlags, ShutdownHow, SockFlags, SockType, SocketOption,
    SocketOptionName, errno::Errno,
};

use crate::{
    GlobalState, ShimPlatform, Task, UserPtr, UserPtrMut,
    syscalls::{
        file::{linux_status_flags, status_flags_change},
        net::SocketOptionValue,
    },
};

pub(crate) struct UnixSocketSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for UnixSocketSubsystem<Platform> {
    type Entry = UnixSocket<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for UnixSocket<Platform> {}

/// C-compatible structure for Unix socket addresses.
const UNIX_PATH_MAX: usize = 108;
#[repr(C)]
pub(super) struct CSockUnixAddr {
    /// Address family (AF_UNIX)
    pub(super) family: i16,
    /// Socket path or abstract address
    pub(super) path: [u8; UNIX_PATH_MAX],
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
    /// Returns the broker address naming `self`, resolving a relative path against the current
    /// working directory of `task`.
    ///
    /// Fails with `EINVAL` for an unnamed address, which names no socket.
    fn to_local<Platform: ShimPlatform>(
        &self,
        task: &Task<Platform>,
    ) -> Result<LocalSocketAddress, Errno> {
        match self {
            UnixSocketAddr::Unnamed => Err(Errno::EINVAL),
            UnixSocketAddr::Abstract(name) => Ok(LocalSocketAddress::Abstract(name.clone())),
            UnixSocketAddr::Path(path) => {
                let resolved = task.fs.borrow().context.read().resolve(path.as_str())?;
                Ok(LocalSocketAddress::Path {
                    path: resolved.to_string(),
                    name: path.as_bytes().to_vec(),
                })
            }
        }
    }
}

impl From<LocalSocketName> for UnixSocketAddr {
    fn from(name: LocalSocketName) -> Self {
        match name {
            LocalSocketName::Unnamed => UnixSocketAddr::Unnamed,
            LocalSocketName::Path(name) => {
                UnixSocketAddr::Path(String::from_utf8_lossy(&name).into_owned())
            }
            LocalSocketName::Abstract(name) => UnixSocketAddr::Abstract(name),
        }
    }
}

/// A Unix domain socket descriptor's open file description.
pub(crate) struct UnixSocket<Platform: ShimPlatform> {
    socket: Arc<LocalSocket<Platform>>,
}

impl<Platform: ShimPlatform> From<LocalSocket<Platform>> for UnixSocket<Platform> {
    fn from(socket: LocalSocket<Platform>) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

impl<Platform: ShimPlatform> UnixSocket<Platform> {
    pub(super) fn new(
        litebox: &litebox::LiteBox<Platform>,
        sock_type: SockType,
        flags: SockFlags,
    ) -> Result<Self, Errno> {
        let socket = litebox.create_local_socket(socket_type(sock_type)?, open_flags(flags))?;
        Ok(socket.into())
    }

    pub(super) fn new_connected_pair(
        litebox: &litebox::LiteBox<Platform>,
        sock_type: SockType,
        flags: SockFlags,
    ) -> Result<(Self, Self), Errno> {
        let (first, second) =
            litebox.create_local_socket_pair(socket_type(sock_type)?, open_flags(flags))?;
        Ok((first.into(), second.into()))
    }

    /// The broker-owned socket, which a child process inherits.
    pub(crate) fn local_socket(&self) -> &Arc<LocalSocket<Platform>> {
        &self.socket
    }

    pub(super) fn is_stream(&self) -> bool {
        self.socket.socket_type() == SocketType::Stream
    }

    /// Binds the socket to `addr`, creating a filesystem node for a path with the permissions
    /// that the umask of `task` allows.
    pub(super) fn bind(&self, task: &Task<Platform>, addr: UnixSocketAddr) -> Result<(), Errno> {
        let address = addr.to_local(task)?;
        let mode = (Mode::RWXU | Mode::RWXG | Mode::RWXO) & !task.fs.borrow().umask();
        self.socket.bind(&address, acting_user(task), mode)?;
        Ok(())
    }

    pub(super) fn listen(&self, backlog: u16) -> Result<(), Errno> {
        self.socket.listen(u32::from(backlog))?;
        Ok(())
    }

    pub(super) fn connect(&self, task: &Task<Platform>, addr: UnixSocketAddr) -> Result<(), Errno> {
        let address = addr.to_local(task)?;
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
        let address = addr.map(|addr| addr.to_local(task)).transpose()?;
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
            flags.contains(ReceiveFlags::DONTWAIT),
        )?;
        if let Some(source_addr) = source_addr
            && !self.is_stream()
        {
            *source_addr = Some(received.source.into());
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
        match global.setsockopt_common(optname, optval, optlen, |so, value| {
            let option = match (so, value) {
                (SocketOption::RCVTIMEO, SocketOptionValue::Timeout(timeout)) => {
                    LocalSocketOption::ReceiveTimeout(timeout)
                }
                (SocketOption::SNDTIMEO, SocketOptionValue::Timeout(timeout)) => {
                    LocalSocketOption::SendTimeout(timeout)
                }
                (SocketOption::LINGER, SocketOptionValue::Timeout(timeout)) => {
                    LocalSocketOption::Linger(timeout)
                }
                (SocketOption::REUSEADDR, SocketOptionValue::U32(val)) => {
                    LocalSocketOption::ReuseAddress(val != 0)
                }
                (SocketOption::KEEPALIVE, SocketOptionValue::U32(val)) => {
                    LocalSocketOption::KeepAlive(val != 0)
                }
                (SocketOption::BROADCAST, SocketOptionValue::U32(val)) => {
                    LocalSocketOption::Broadcast(val != 0)
                }
                _ => unreachable!(),
            };
            Ok(self.socket.set_option(option)?)
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
        if let SocketOptionName::Socket(
            SocketOption::RCVTIMEO
            | SocketOption::SNDTIMEO
            | SocketOption::LINGER
            | SocketOption::REUSEADDR
            | SocketOption::KEEPALIVE
            | SocketOption::BROADCAST,
        ) = optname
        {
            let options = self.socket.options()?;
            return global.getsockopt_common(optname, optval, len, |sopt| match sopt {
                SocketOption::RCVTIMEO => SocketOptionValue::Timeout(options.receive_timeout),
                SocketOption::SNDTIMEO => SocketOptionValue::Timeout(options.send_timeout),
                SocketOption::LINGER => SocketOptionValue::Timeout(options.linger),
                SocketOption::REUSEADDR => SocketOptionValue::U32(u32::from(options.reuse_address)),
                SocketOption::KEEPALIVE => SocketOptionValue::U32(u32::from(options.keep_alive)),
                SocketOption::BROADCAST => SocketOptionValue::U32(u32::from(options.broadcast)),
                _ => unreachable!(),
            });
        }

        let val: u32 = match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS => return Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(so) => match so {
                // handled above
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
                SocketOption::RCVBUF | SocketOption::SNDBUF => LOCAL_SOCKET_BUFFER_SIZE,
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
        let mode = match how {
            ShutdownHow::Read => ShutdownMode::Read,
            ShutdownHow::Write => ShutdownMode::Write,
            ShutdownHow::Both => ShutdownMode::Both,
        };
        self.socket.shutdown(mode)?;
        Ok(())
    }

    /// Returns the `F_GETFL` flags of the socket, which every descriptor sharing it sees.
    pub(super) fn get_status(&self) -> Result<OFlags, Errno> {
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
        fd: &TypedFd<UnixSocketSubsystem<Platform>>,
        f: impl FnOnce(&UnixSocket<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts a Unix socket this process inherited from its parent as `handle`.
    pub(super) fn adopt_inherited_unix_socket(
        &self,
        handle: ObjectHandle,
    ) -> Result<TypedFd<UnixSocketSubsystem<Platform>>, ProcessError> {
        let socket = self.litebox.adopt_inherited_local_socket(handle)?;
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

fn socket_type(sock_type: SockType) -> Result<SocketType, Errno> {
    match sock_type {
        SockType::Stream => Ok(SocketType::Stream),
        SockType::Datagram => Ok(SocketType::Datagram),
        e => {
            log_unsupported!("Unsupported unix socket type: {:?}", e);
            Err(Errno::ESOCKTNOSUPPORT)
        }
    }
}

fn open_flags(flags: SockFlags) -> FileOpenFlags {
    if flags.contains(SockFlags::NONBLOCK) {
        FileOpenFlags::NONBLOCKING
    } else {
        FileOpenFlags::NONE
    }
}

fn acting_user<Platform: ShimPlatform>(task: &Task<Platform>) -> FileUser {
    task.fs.borrow().context.read().acting_user()
}
