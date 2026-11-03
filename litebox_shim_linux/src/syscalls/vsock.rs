// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `AF_VSOCK` stream sockets for the Linux shim layer.
//!
//! Each socket is a LiteBox [`vsock_socket::VsockSocket`], backed by the broker's vsock provider,
//! and reaches only the host (CID [`VsockCid::HOST`]). Without a provider, creating one fails
//! with `EAFNOSUPPORT`.
//!
//! Stream sockets only; `MSG_PEEK`, `MSG_WAITALL`, and socket options but `SO_ERROR`, `SO_TYPE`,
//! `SO_DOMAIN` and `SO_PROTOCOL` are not supported.
//!
//! As in Linux, addresses are copied first, then a bind checks its address, a connect the
//! socket's state before its address, and a send never parses its destination, which fails it.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use litebox::{
    event::{Events, IOPollable, observer::Observer, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    process::ProcessError,
    vsock_socket::{self, errors::VsockSocketError},
};
use litebox_broker_protocol::{
    ObjectHandle,
    socket::{SocketError, SocketType},
    vsock_socket::{VsockAddress, VsockCid, VsockPort},
};
use litebox_common_linux::{
    AddressFamily, OFlags, PF_VSOCK, ReceiveFlags, SendFlags, ShutdownHow, SockAddrVm, SockFlags,
    SockType, SocketOption, SocketOptionLevel, VMADDR_FLAG_TO_HOST, errno::Errno,
};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use zerocopy::{FromBytes as _, IntoBytes as _};

use crate::{
    GlobalState, ShimPlatform, UserPtr, UserPtrMut,
    syscalls::{
        file::{linux_status_flags, status_flags_change},
        net::{SocketAddress, open_flags, shutdown_mode},
    },
};

// TODO: add `SO_PROTOCOL` and `SO_DOMAIN` to `SocketOption`, answered for every family as on
// Linux, and drop these.
/// `SO_PROTOCOL`, which [`SocketOption`] does not have.
const SO_PROTOCOL: u32 = 38;
/// `SO_DOMAIN`, which [`SocketOption`] does not have.
const SO_DOMAIN: u32 = 39;

pub(crate) struct VsockSocketSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for VsockSocketSubsystem<Platform> {
    type Entry = VsockSocket<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for VsockSocket<Platform> {}

pub(crate) type VsockSocketFd<Platform> = TypedFd<VsockSocketSubsystem<Platform>>;

/// Parses a `sockaddr_vm` of `bytes.len()` bytes as Linux does: the whole structure, of family
/// `AF_VSOCK`, with no flags but `VMADDR_FLAG_TO_HOST`. Like Linux, the reserved and zero bytes
/// are not checked.
fn parse_sockaddr(bytes: &[u8]) -> Result<VsockAddress, Errno> {
    let (addr, _) = SockAddrVm::read_from_prefix(bytes).map_err(|_| Errno::EINVAL)?;
    if u32::from(addr.svm_family) != AddressFamily::VSOCK as u32
        || addr.svm_flags & !VMADDR_FLAG_TO_HOST != 0
    {
        return Err(Errno::EINVAL);
    }
    Ok(VsockAddress {
        cid: VsockCid(addr.svm_cid),
        port: VsockPort(addr.svm_port),
    })
}

/// `sizeof(struct sockaddr_storage)`, the longest address Linux copies.
const SOCKADDR_STORAGE_LEN: usize = 128;

/// Copies the address of `addrlen` bytes at `sockaddr` as Linux's `move_addr_to_kernel` does:
/// above [`SOCKADDR_STORAGE_LEN`] bytes fails with `EINVAL`, a fault with `EFAULT`, and 0 bytes
/// copies nothing.
fn copy_sockaddr<Platform: ShimPlatform>(
    sockaddr: UserPtr<u8>,
    addrlen: usize,
) -> Result<Box<[u8]>, Errno> {
    if addrlen > SOCKADDR_STORAGE_LEN {
        return Err(Errno::EINVAL);
    }
    sockaddr
        .to_owned_slice::<Platform>(addrlen)
        .ok_or(Errno::EFAULT)
}

/// Copies a bind's address, which must be a vsock address (else `EINVAL`).
pub(super) fn read_bind_address<Platform: ShimPlatform>(
    sockaddr: UserPtr<u8>,
    addrlen: usize,
) -> Result<VsockAddress, Errno> {
    parse_sockaddr(&copy_sockaddr::<Platform>(sockaddr, addrlen)?)
}

/// Copies a connect's address, returning it if it is a vsock address; see
/// [`VsockSocket::connect`] for an invalid one.
pub(super) fn read_connect_address<Platform: ShimPlatform>(
    sockaddr: UserPtr<u8>,
    addrlen: usize,
) -> Result<Option<VsockAddress>, Errno> {
    Ok(parse_sockaddr(&copy_sockaddr::<Platform>(sockaddr, addrlen)?).ok())
}

/// Copies a `sendto`'s destination, never parsing it, and returns whether there is one: a
/// non-null `addr` of non-zero `addrlen`.
pub(super) fn copy_destination<Platform: ShimPlatform>(
    addr: Option<UserPtr<u8>>,
    addrlen: usize,
) -> Result<bool, Errno> {
    let Some(addr) = addr.filter(|addr| !addr.is_null()) else {
        return Ok(false);
    };
    copy_sockaddr::<Platform>(addr, addrlen)?;
    Ok(addrlen != 0)
}

/// As [`copy_destination`], for a `sendmsg`, which clamps a length above
/// [`SOCKADDR_STORAGE_LEN`] bytes (but fails for a negative one).
pub(super) fn copy_msg_destination<Platform: ShimPlatform>(
    name: UserPtr<u8>,
    namelen: u32,
) -> Result<bool, Errno> {
    if name.is_null() {
        return Ok(false);
    }
    if i32::try_from(namelen).is_err() {
        return Err(Errno::EINVAL);
    }
    copy_destination::<Platform>(Some(name), (namelen as usize).min(SOCKADDR_STORAGE_LEN))
}

/// Reads the vsock address of `addrlen` bytes at `sockaddr`: `EINVAL` unless they hold a whole
/// `sockaddr_vm`.
pub(super) fn read_sockaddr<Platform: ShimPlatform>(
    sockaddr: UserPtr<u8>,
    addrlen: usize,
) -> Result<VsockAddress, Errno> {
    let addr = super::read_from_user::<SockAddrVm, Platform>(sockaddr, addrlen)?;
    parse_sockaddr(addr.as_bytes())
}

/// Writes `addr`, truncated to `capacity` bytes, to `dst`, returning its full length.
pub(super) fn write_sockaddr<Platform: ShimPlatform>(
    addr: VsockAddress,
    dst: UserPtrMut<u8>,
    capacity: usize,
) -> Result<usize, Errno> {
    let addr = SockAddrVm {
        svm_family: AddressFamily::VSOCK as u16,
        svm_port: addr.port.0,
        svm_cid: addr.cid.0,
        ..SockAddrVm::default()
    };
    let bytes = addr.as_bytes();
    let copied = bytes.len().min(capacity);
    if copied != 0 {
        dst.write_slice_at_offset::<Platform>(0, &bytes[..copied])
            .ok_or(Errno::EFAULT)?;
    }
    Ok(bytes.len())
}

fn check_receive_flags(flags: ReceiveFlags) -> Result<(), Errno> {
    let unsupported =
        ReceiveFlags::OOB | ReceiveFlags::ERRQUEUE | ReceiveFlags::PEEK | ReceiveFlags::WAITALL;
    if flags.intersects(unsupported) {
        log_unsupported!("vsock receive flags {flags:?}");
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(())
}

/// A vsock socket descriptor's open file description.
pub(crate) struct VsockSocket<Platform: ShimPlatform> {
    socket: Arc<vsock_socket::VsockSocket<Platform>>,
}

impl<Platform: ShimPlatform> From<vsock_socket::VsockSocket<Platform>> for VsockSocket<Platform> {
    fn from(socket: vsock_socket::VsockSocket<Platform>) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

impl<Platform: ShimPlatform> VsockSocket<Platform> {
    /// Creates a socket of type `ty` for `protocol`, which must be 0 or `PF_VSOCK`; only stream
    /// sockets are supported.
    pub(super) fn new(
        litebox: &litebox::LiteBox<Platform>,
        ty: SockType,
        protocol: u8,
        flags: SockFlags,
    ) -> Result<Self, Errno> {
        if protocol != 0 && protocol != PF_VSOCK {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let SockType::Stream = ty else {
            log_unsupported!("vsock socket type {ty:?}");
            return Err(Errno::ESOCKTNOSUPPORT);
        };
        match litebox.create_vsock_socket(SocketType::Stream, open_flags(flags)) {
            Ok(socket) => Ok(socket.into()),
            Err(VsockSocketError::Unsupported) => Err(Errno::EAFNOSUPPORT),
            Err(error) => Err(error.into()),
        }
    }

    /// The LiteBox socket, which a child process inherits.
    pub(crate) fn vsock_socket(&self) -> &Arc<vsock_socket::VsockSocket<Platform>> {
        &self.socket
    }

    /// Binds the socket to `addr`, of the `AF_VSOCK` family, as Linux requires.
    pub(super) fn bind(&self, addr: SocketAddress) -> Result<(), Errno> {
        let SocketAddress::Vsock(address) = addr else {
            return Err(Errno::EINVAL);
        };
        Ok(self.socket.bind(address)?)
    }

    pub(super) fn listen(&self, backlog: u16) -> Result<(), Errno> {
        Ok(self.socket.listen(u32::from(backlog))?)
    }

    /// Accepts a connection, returning it and its peer's address; `flags` sets the new socket's
    /// status flags only.
    pub(super) fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: SockFlags,
    ) -> Result<(Self, VsockAddress), Errno> {
        let (accepted, peer) = self.socket.accept(cx, open_flags(flags), false)?;
        Ok((accepted.into(), peer))
    }

    /// Connects as Linux does: a blocking connect waits for the host's answer, a nonblocking one
    /// fails with `EINPROGRESS`, and a signal cancels a blocking one with `EINTR`, never restarted.
    ///
    /// The socket's state decides before the address, as on Linux, so without a valid vsock
    /// `address` (`None`) the connect goes to the broker as [`VsockCid::ANY`], which bypasses the
    /// policy and which the provider fails with `NetworkUnreachable` (reported as `EINVAL`) only
    /// after its state checks.
    pub(super) fn connect(
        &self,
        cx: &WaitContext<'_, Platform>,
        address: Option<VsockAddress>,
    ) -> Result<(), Errno> {
        let unreachable = VsockAddress {
            cid: VsockCid::ANY,
            port: VsockPort::ANY,
        };
        let result = self
            .socket
            .connect(cx, address.unwrap_or(unreachable), false)
            .map_err(Errno::from);
        match result {
            Err(Errno::ENETUNREACH) if address.is_none() => Err(Errno::EINVAL),
            result => result,
        }
    }

    /// Sends `buf`, waiting for room unless `flags` has `MSG_DONTWAIT` or the socket is
    /// nonblocking; `MSG_NOSIGNAL` is left to the caller.
    ///
    /// As in Linux, `MSG_OOB` fails, other flags are ignored, and a `destination`, whatever its
    /// content, fails with `EISCONN` if the socket is connected, else with `EOPNOTSUPP`.
    pub(super) fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: impl WriteBuffer,
        flags: SendFlags,
        destination: bool,
    ) -> Result<usize, Errno> {
        if flags.contains(SendFlags::OOB) {
            return Err(Errno::EOPNOTSUPP);
        }
        if destination {
            // An empty send checks the state only.
            return Err(match self.socket.send(cx, &[][..], true) {
                Ok(_) | Err(VsockSocketError::Socket(SocketError::Shutdown)) => Errno::EISCONN,
                Err(VsockSocketError::Socket(SocketError::NotConnected)) => Errno::EOPNOTSUPP,
                Err(error) => error.into(),
            });
        }
        Ok(self
            .socket
            .send(cx, buf, flags.contains(SendFlags::DONTWAIT))?)
    }

    /// Receives into `buf`, waiting unless `flags` has `MSG_DONTWAIT` or the socket is
    /// nonblocking. `MSG_PEEK`, `MSG_WAITALL`, and, as in Linux, `MSG_OOB` and `MSG_ERRQUEUE`
    /// fail; other flags are ignored.
    pub(super) fn receive(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: impl ReadBuffer,
        flags: ReceiveFlags,
    ) -> Result<usize, Errno> {
        check_receive_flags(flags)?;
        Ok(self
            .socket
            .receive(cx, buf, flags.contains(ReceiveFlags::DONTWAIT))?)
    }

    /// Waits as a receive does until data waits or the stream ended, taking none: whether data
    /// waits. A receive into memory it cannot write uses this, so that, as in Linux, the
    /// socket's state comes before `EFAULT`, and the data stays.
    pub(super) fn probe(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: ReceiveFlags,
    ) -> Result<bool, Errno> {
        check_receive_flags(flags)?;
        Ok(self
            .socket
            .probe(cx, flags.contains(ReceiveFlags::DONTWAIT))?)
    }

    pub(super) fn shutdown(&self, how: ShutdownHow) -> Result<(), Errno> {
        Ok(self.socket.shutdown(shutdown_mode(how))?)
    }

    /// The socket's address, or, as in Linux, `VMADDR_CID_ANY` and `VMADDR_PORT_ANY` if it is
    /// unbound.
    pub(super) fn get_local_addr(&self) -> Result<VsockAddress, Errno> {
        Ok(self.socket.name(false)?.unwrap_or(VsockAddress {
            cid: VsockCid::ANY,
            port: VsockPort::ANY,
        }))
    }

    pub(super) fn get_peer_addr(&self) -> Result<VsockAddress, Errno> {
        self.socket.name(true)?.ok_or(Errno::ENOTCONN)
    }

    /// Writes the value of option `optname` at `level`, truncated to `len` bytes, to `optval`,
    /// returning its length: `SO_ERROR`, which takes the pending error, `SO_TYPE`, `SO_DOMAIN`,
    /// and `SO_PROTOCOL`; any other fails with `ENOPROTOOPT`.
    pub(super) fn getsockopt(
        &self,
        level: u32,
        optname: u32,
        optval: UserPtrMut<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        if level != SocketOptionLevel::SOCKET as u32 {
            return Err(Errno::ENOPROTOOPT);
        }
        let value: u32 = match optname {
            SO_DOMAIN => AddressFamily::VSOCK as u32,
            SO_PROTOCOL => 0,
            _ => match SocketOption::try_from(optname) {
                Ok(SocketOption::TYPE) => SockType::Stream as u32,
                Ok(SocketOption::ERROR) => self.socket.take_error()?.map_or(0, |error| {
                    i32::from(Errno::from(VsockSocketError::Socket(error))).cast_unsigned()
                }),
                _ => {
                    log_unsupported!("vsock getsockopt(optname = {optname})");
                    return Err(Errno::ENOPROTOOPT);
                }
            },
        };
        super::write_to_user::<_, Platform>(value, optval, len)
    }

    /// Returns the `F_GETFL` flags, which every descriptor sharing the socket sees.
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
    /// Runs `f` on the vsock socket at `fd`, without holding the descriptor table.
    pub(crate) fn with_vsock_socket<R>(
        &self,
        fd: &VsockSocketFd<Platform>,
        f: impl FnOnce(&VsockSocket<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts a vsock socket this process inherited from its parent as `handle`.
    pub(super) fn adopt_inherited_vsock_socket(
        &self,
        handle: ObjectHandle,
    ) -> Result<VsockSocketFd<Platform>, ProcessError> {
        let socket = self.litebox.adopt_inherited_vsock_socket(handle)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<VsockSocketSubsystem<Platform>>(VsockSocket::from(socket)))
    }
}

impl<Platform: ShimPlatform> IOPollable for VsockSocket<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.socket.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.socket.check_io_events()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use litebox_broker_protocol::vsock_socket::{VsockAddress, VsockCid, VsockPort};
    use litebox_common_linux::{AddressFamily, errno::Errno};

    use super::parse_sockaddr;

    fn sockaddr(cid: u32, port: u32) -> Vec<u8> {
        let mut bytes = (AddressFamily::VSOCK as u16).to_ne_bytes().to_vec();
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&port.to_ne_bytes());
        bytes.extend_from_slice(&cid.to_ne_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }

    #[test]
    fn sockaddrs_parse_as_linux_validates_them() {
        let addr = VsockAddress {
            cid: VsockCid(3),
            port: VsockPort(1024),
        };
        assert_eq!(parse_sockaddr(&sockaddr(3, 1024)), Ok(addr));
        let mut long = sockaddr(3, 1024);
        long.extend_from_slice(&[0xff; 16]);
        assert_eq!(parse_sockaddr(&long), Ok(addr));
        assert_eq!(parse_sockaddr(&sockaddr(3, 1024)[..15]), Err(Errno::EINVAL));
        // Reserved and zero bytes are ignored, `VMADDR_FLAG_TO_HOST` is allowed, no other flag.
        let mut reserved = sockaddr(3, 1024);
        reserved[2] = 0xff;
        reserved[13..].fill(0xff);
        assert_eq!(parse_sockaddr(&reserved), Ok(addr));
        let mut to_host = sockaddr(3, 1024);
        to_host[12] = 1;
        assert_eq!(parse_sockaddr(&to_host), Ok(addr));
        let mut flags = sockaddr(3, 1024);
        flags[12] = 2;
        assert_eq!(parse_sockaddr(&flags), Err(Errno::EINVAL));
        let mut inet = sockaddr(3, 1024);
        inet[..2].copy_from_slice(&(AddressFamily::INET as u16).to_ne_bytes());
        assert_eq!(parse_sockaddr(&inet), Err(Errno::EINVAL));
    }
}
