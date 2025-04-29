use core::sync::atomic::AtomicU32;

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    string::String,
    vec::Vec,
};
use litebox::{
    fd::FileFd,
    fs::{FileSystem, Mode, OFlags},
    platform::RawConstPointer,
    sync::RawSyncPrimitivesProvider,
};
use litebox_common_linux::{IoEvents, SockFlags, SockType, SocketOptionName, errno::Errno};

use crate::{ConstPtr, event::Pollee, litebox_fs};

use super::net::{SocketAddress, SocketOptions};

const DEFAULT_BUF_SIZE: usize = 65536;

pub(super) enum SocketUnixAddr {
    Unnamed,
    Path(String),
    Abstract(Vec<u8>),
}

impl SocketUnixAddr {
    fn is_unnamed(&self) -> bool {
        matches!(self, SocketUnixAddr::Unnamed)
    }

    fn bind(self, is_server: bool) -> Result<SocketBoundUnixAddr, Errno> {
        let bound = match self {
            SocketUnixAddr::Path(path) => {
                let flags = if is_server {
                    // Create the file with Read and Write permissions
                    // and fail if the file already exists
                    OFlags::CREAT | OFlags::EXCL | OFlags::RDWR
                } else {
                    // Open the file with Write permissions
                    OFlags::WRONLY
                };
                // TODO: resolve the path to an absolute path
                let file = litebox_fs().open(path.as_str(), flags, Mode::RUSR | Mode::WUSR)?;
                SocketBoundUnixAddr::Path((path, Some(file)))
            }
            _ => {
                todo!()
            }
        };
        Ok(bound)
    }

    fn to_key(&self) -> Result<SocketBoundUnixAddrKey, Errno> {
        match self {
            SocketUnixAddr::Path(path) => Ok(SocketBoundUnixAddrKey::Path(path.clone())),
            SocketUnixAddr::Abstract(addr) => Ok(SocketBoundUnixAddrKey::Abstract(addr.clone())),
            _ => Err(Errno::EINVAL),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
enum SocketBoundUnixAddrKey {
    Path(String),
    Abstract(Vec<u8>),
}

enum SocketBoundUnixAddr {
    Path((String, Option<FileFd>)),
    Abstract(Vec<u8>),
}

impl SocketBoundUnixAddr {
    fn to_key(&self) -> SocketBoundUnixAddrKey {
        match self {
            SocketBoundUnixAddr::Path((path, _)) => SocketBoundUnixAddrKey::Path(path.clone()),
            SocketBoundUnixAddr::Abstract(addr) => SocketBoundUnixAddrKey::Abstract(addr.clone()),
        }
    }
}

impl Clone for SocketBoundUnixAddr {
    fn clone(&self) -> Self {
        match self {
            SocketBoundUnixAddr::Path((path, fd)) => {
                let dup_file = litebox_fs()
                    .open(path.as_str(), OFlags::RDONLY, Mode::empty())
                    .unwrap();
                SocketBoundUnixAddr::Path((path.clone(), Some(dup_file)))
            }
            SocketBoundUnixAddr::Abstract(addr) => SocketBoundUnixAddr::Abstract(addr.clone()),
        }
    }
}

impl Drop for SocketBoundUnixAddr {
    fn drop(&mut self) {
        match self {
            SocketBoundUnixAddr::Path((_, fd)) => {
                // Close the file descriptor
                if let Some(file) = fd.take() {
                    let _ = litebox_fs().close(file);
                }
            }
            SocketBoundUnixAddr::Abstract(_) => {}
        }
    }
}

struct AddrView {
    addr: Option<SocketBoundUnixAddr>,
    peer: Option<SocketBoundUnixAddr>,
}

impl AddrView {
    fn new_pair(
        addr: Option<SocketBoundUnixAddr>,
        peer: Option<SocketBoundUnixAddr>,
    ) -> (Self, Self) {
        let first = Self {
            addr: addr.clone(),
            peer: peer.clone(),
        };
        let second = Self {
            addr: peer,
            peer: addr,
        };
        (first, second)
    }

    fn addr(&self) -> Option<&SocketBoundUnixAddr> {
        self.addr.as_ref()
    }

    fn peer_addr(&self) -> Option<&SocketBoundUnixAddr> {
        self.peer.as_ref()
    }
}

struct UnixInitStreamSocket {
    addr: Option<SocketBoundUnixAddr>,
}

impl UnixInitStreamSocket {
    fn new() -> Self {
        Self { addr: None }
    }

    fn into_connected(
        self,
        addr: SocketBoundUnixAddr,
    ) -> (UnixConnectedSocket, UnixConnectedSocket) {
        UnixConnectedSocket::new_pair(self.addr, Some(addr))
    }

    fn connect(
        self,
        addr: SocketBoundUnixAddr,
        is_nonblocking: bool,
    ) -> Result<UnixConnectedSocket, (Errno, Self)> {
        let guard = UNIX_ADDR_TABLE.read();
        let entry = match guard.get(&addr.to_key()) {
            Some(v) => v,
            None => return Err((Errno::ECONNREFUSED, self)),
        };
        match entry {
            UnixEntry::Stream(backlog) => backlog.connect(self, is_nonblocking),
            _ => Err((Errno::EPROTOTYPE, self)),
        }
    }
}

struct UnixConnectedSocket {
    addr: AddrView,
    reader: alloc::sync::Arc<crate::channel::Consumer<u8>>,
    writer: alloc::sync::Arc<crate::channel::Producer<u8>>,
    // peer_cred: Ucred,
}

impl UnixConnectedSocket {
    fn new_pair(
        addr: Option<SocketBoundUnixAddr>,
        peer_addr: Option<SocketBoundUnixAddr>,
    ) -> (UnixConnectedSocket, UnixConnectedSocket) {
        let litebox = crate::litebox();
        let (writer_peer, reader) = crate::channel::Channel::new(DEFAULT_BUF_SIZE, litebox).split();
        let (writer, reader_peer) = crate::channel::Channel::new(DEFAULT_BUF_SIZE, litebox).split();

        let (addr, addr_peer) = AddrView::new_pair(addr, peer_addr);
        // let peer_cred = get_current_cred();
        (
            UnixConnectedSocket {
                addr,
                reader,
                writer,
                // peer_cred,
            },
            UnixConnectedSocket {
                addr: addr_peer,
                reader: reader_peer,
                writer: writer_peer,
                // peer_cred,
            },
        )
    }
}

enum UnixSocketState {
    InitStream(UnixInitStreamSocket),
    ConnectedStream(UnixConnectedSocket),
}

pub(crate) struct UnixSocketFile<Platform: RawSyncPrimitivesProvider> {
    state: litebox::sync::RwLock<Platform, Option<UnixSocketState>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    options: litebox::sync::Mutex<Platform, SocketOptions>,
}

impl<Platform: RawSyncPrimitivesProvider> UnixSocketFile<Platform> {
    pub(crate) fn new(
        ty: SockType,
        flags: SockFlags,
        litebox: &litebox::LiteBox<Platform>,
    ) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
        let state: UnixSocketState = match ty {
            SockType::Stream => UnixSocketState::InitStream(UnixInitStreamSocket::new()),
            SockType::Datagram => todo!(),
            _ => todo!(),
        };

        Self {
            state: litebox.sync().new_rwlock(Some(state)),
            status: AtomicU32::new(status.bits()),
            options: litebox.sync().new_mutex(SocketOptions::default()),
        }
    }

    pub(super) fn connect(&self, sock_addr: SocketAddress) -> Result<(), Errno> {
        let SocketAddress::Unix(addr) = sock_addr else {
            return Err(Errno::EAFNOSUPPORT);
        };
        match self.state.read().as_ref().unwrap() {
            UnixSocketState::InitStream(_) => {}
            // UnixSocketState::ConnectedDatagram(_)
            // | UnixSocketState::BoundDatagram(_)
            // | UnixSocketState::InitDatagram(_)
            // | UnixSocketState::ListenStream(_) => return Err(EPROTOTYPE),
            UnixSocketState::ConnectedStream(_) => return Err(Errno::EISCONN),
        }

        let bound = addr.bind(false)?;
        let mut state = self.state.write();
        let inner = state.take().unwrap();
        let new_state = match inner {
            UnixSocketState::InitStream(init) => {
                match init.connect(bound, self.get_status().contains(OFlags::NONBLOCK)) {
                    Ok(connected) => UnixSocketState::ConnectedStream(connected),
                    Err((e, init)) => {
                        *state = Some(UnixSocketState::InitStream(init));
                        return Err(e);
                    }
                }
            }
            v => v,
        };

        *state = Some(new_state);
        Ok(())
    }

    pub(super) fn setsockopt(
        &self,
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
                    |optval| -> Result<Option<core::time::Duration>, Errno> {
                        if optlen < size_of::<litebox_common_linux::Timeval>() {
                            return Err(Errno::EINVAL);
                        }
                        let optval: ConstPtr<litebox_common_linux::Timeval> =
                            unsafe { core::mem::transmute(optval) };
                        let timeval = unsafe { optval.read_at_offset(0) }
                            .ok_or(Errno::EFAULT)?
                            .into_owned();
                        let d = core::time::Duration::try_from(timeval)?;
                        if d.is_zero() { Ok(None) } else { Ok(Some(d)) }
                    };
                match so {
                    litebox_common_linux::SocketOption::RCVTIMEO => {
                        self.options.lock().recv_timeout = read_timeval_as_duration(optval)?;
                        return Ok(());
                    }
                    litebox_common_linux::SocketOption::SNDTIMEO => {
                        self.options.lock().send_timeout = read_timeval_as_duration(optval)?;
                        return Ok(());
                    }
                    _ => {}
                }

                if optlen < size_of::<u32>() {
                    return Err(Errno::EINVAL);
                }
                let optval: ConstPtr<u32> = unsafe { core::mem::transmute(optval) };
                let val = unsafe { optval.read_at_offset(0) }
                    .ok_or(Errno::EFAULT)?
                    .into_owned();
                match so {
                    litebox_common_linux::SocketOption::TYPE => return Err(Errno::EOPNOTSUPP),
                    // no effect on unix
                    litebox_common_linux::SocketOption::REUSEADDR => {
                        self.options.lock().reuse_address = val != 0
                    }
                    // no effect on unix
                    litebox_common_linux::SocketOption::KEEPALIVE => {
                        self.options.lock().keep_alive = val != 0;
                    }
                    _ => {
                        todo!();
                    }
                }
                Ok(())
            }
            SocketOptionName::TCP(_) => Err(Errno::EINVAL),
        }
    }

    crate::syscalls::common_functions_for_file_status!();
}

struct Backlog<Platform: RawSyncPrimitivesProvider> {
    addr: SocketBoundUnixAddr,
    pollee: Pollee,
    backlog: AtomicU32,
    // Set it to None when shutdown
    sockets: litebox::sync::Mutex<Platform, Option<VecDeque<UnixConnectedSocket>>>,
    // ucred: Ucred,
}

impl<Platform: RawSyncPrimitivesProvider> Backlog<Platform> {
    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::empty();
        let limit = self.backlog.load(core::sync::atomic::Ordering::Relaxed) as usize;
        if let Some(sockets) = self.sockets.lock().as_ref() {
            if sockets.len() < limit {
                events.insert(IoEvents::OUT);
            }
            if sockets.len() > 0 {
                events.insert(IoEvents::IN);
            }
        } else {
            // the server socket is shutdown
            events.insert(IoEvents::HUP);
        }

        events
    }

    fn try_connect(
        &self,
        init: UnixInitStreamSocket,
    ) -> Result<UnixConnectedSocket, (Errno, UnixInitStreamSocket)> {
        let mut locked_sockets = self.sockets.lock();
        let Some(sockets) = &mut *locked_sockets else {
            // the server socket is shutdown
            return Err((Errno::ECONNREFUSED, init));
        };

        let limit = self.backlog.load(core::sync::atomic::Ordering::Relaxed) as usize;
        if sockets.len() >= limit {
            return Err((Errno::EAGAIN, init));
        }

        let (mut client, server) = init.into_connected(self.addr.clone());
        sockets.push_back(server);

        // Though the server socket is created by the current task, the peer_cred should be the
        // one from the listening socket.
        // client.peer_cred = self.ucred;
        Ok(client)
    }

    fn connect(
        &self,
        mut init: UnixInitStreamSocket,
        is_nonblocking: bool,
    ) -> Result<UnixConnectedSocket, (Errno, UnixInitStreamSocket)> {
        if is_nonblocking {
            self.try_connect(init)
        } else {
            let poller = alloc::sync::Arc::new(crate::event::Poller::new());
            let revents = self.pollee.poll(
                IoEvents::OUT,
                Some(alloc::sync::Arc::downgrade(&poller) as _),
                || self.check_io_events(),
            );
            if revents.is_empty() {
                if let Err(e) = poller.wait_or_timeout(&mut None) {
                    return Err((e, init));
                }
            }

            loop {
                init = match self.try_connect(init) {
                    Err((Errno::EAGAIN, init)) => init,
                    ret => return ret,
                };

                if let Err(e) = poller.wait_or_timeout(&mut None) {
                    return Err((e, init));
                }
            }
        }
    }
}

enum UnixEntry<Platform: RawSyncPrimitivesProvider> {
    Datagram(crate::channel::Producer<u8>),
    Stream(alloc::sync::Arc<Backlog<Platform>>),
}

lazy_static::lazy_static! {
    static ref UNIX_ADDR_TABLE: litebox::sync::RwLock<
        litebox_platform_multiplex::Platform,
        BTreeMap<SocketBoundUnixAddrKey, UnixEntry<litebox_platform_multiplex::Platform>>
    > = crate::litebox().sync().new_rwlock(BTreeMap::new());
}
