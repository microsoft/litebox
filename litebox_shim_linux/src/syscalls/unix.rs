// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix domain socket implementation for the Linux shim layer.

use core::{
    sync::atomic::{AtomicU16, AtomicU32, Ordering},
    time::Duration,
};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    event::{
        Events, IOPollable,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fs::{FileSystem, Mode, OFlags, errors::OpenError},
    sync::{Mutex, RwLock},
};
use litebox_common_linux::{
    IpOption, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption, SocketOptionName,
    errno::Errno,
};

use crate::{
    ConstPtr, FileFd, GlobalState, MutPtr, Task,
    channel::{Channel, ReadEnd, WriteEnd},
    syscalls::net::SocketOptions,
};

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

/// A bound Unix socket address with associated resources.
///
/// For path-based sockets, this includes a file descriptor to ensure
/// the socket file remains accessible. The file is automatically closed
/// when this structure is dropped.
enum UnixBoundSocketAddr {
    Path((String, FileFd, Arc<GlobalState>)),
    Abstract(Vec<u8>),
}

/// Key type for indexing Unix socket addresses in the global address table.
///
/// This is used internally to track which addresses are currently bound
/// by listening sockets.
#[derive(PartialEq, Eq, Hash, Debug, Ord, PartialOrd)]
pub(crate) enum UnixSocketAddrKey {
    // TODO: add inode reference once the file system supports it.
    Path(String),
    Abstract(Vec<u8>),
}

impl UnixSocketAddr {
    /// Returns true if this is an unnamed socket address.
    fn is_unnamed(&self) -> bool {
        matches!(self, UnixSocketAddr::Unnamed)
    }

    /// Binds this address to the filesystem or abstract namespace.
    ///
    /// # Arguments
    ///
    /// * `task` - The current task context
    /// * `is_server` - Whether this is a server socket (creates the file if true)
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be bound (e.g., file doesn't exist,
    /// permission denied).
    fn bind(self, task: &Task, is_server: bool) -> Result<UnixBoundSocketAddr, Errno> {
        match self {
            UnixSocketAddr::Path(path) => {
                let flags = if is_server {
                    // create the socket file if not exists;
                    // use O_EXCL to ensure exclusive creation
                    OFlags::CREAT | OFlags::EXCL | OFlags::RDWR
                } else {
                    OFlags::RDWR
                };
                // TODO: extend fs to support creating sock file (i.e., with type `InodeType::Socket`)
                let file = task
                    .global
                    .fs
                    .open(
                        path.as_str(),
                        flags,
                        Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                    )
                    .map_err(|err| match err {
                        OpenError::AlreadyExists => Errno::EADDRINUSE,
                        other => Errno::from(other),
                    })?;
                Ok(UnixBoundSocketAddr::Path((path, file, task.global.clone())))
            }
            UnixSocketAddr::Abstract(data) => {
                // TODO: check if the abstract address is already in use
                Ok(UnixBoundSocketAddr::Abstract(data))
            }
            UnixSocketAddr::Unnamed => todo!("autobind for unnamed unix socket"),
        }
    }

    /// Converts this address to a key for the global address table.
    ///
    /// Returns `None` for unnamed addresses, which cannot be looked up.
    fn to_key(&self) -> Option<UnixSocketAddrKey> {
        match self {
            Self::Unnamed => None,
            Self::Path(path) => Some(UnixSocketAddrKey::Path(path.clone())),
            Self::Abstract(addr) => Some(UnixSocketAddrKey::Abstract(addr.clone())),
        }
    }
}

impl UnixBoundSocketAddr {
    /// Converts this bound address to a key for the global address table.
    fn to_key(&self) -> UnixSocketAddrKey {
        match self {
            Self::Path((path, ..)) => UnixSocketAddrKey::Path(path.clone()),
            Self::Abstract(addr) => UnixSocketAddrKey::Abstract(addr.clone()),
        }
    }
}

impl Drop for UnixBoundSocketAddr {
    fn drop(&mut self) {
        match self {
            Self::Path((_, file, global)) => {
                let _ = global.fs.close(file);
            }
            Self::Abstract(_) => {}
        }
    }
}

impl From<&UnixBoundSocketAddr> for UnixSocketAddr {
    fn from(addr: &UnixBoundSocketAddr) -> Self {
        match addr {
            UnixBoundSocketAddr::Path((path, ..)) => UnixSocketAddr::Path(path.clone()),
            UnixBoundSocketAddr::Abstract(data) => UnixSocketAddr::Abstract(data.clone()),
        }
    }
}

/// Represents a Unix stream socket in its initial state.
///
/// This is the state immediately after socket creation, before the socket
/// has been connected, or put into listening mode.
struct UnixInitStream {
    /// Optional bound address for this socket
    addr: Option<UnixBoundSocketAddr>,
    pollee: Pollee<crate::Platform>,
}

impl UnixInitStream {
    fn new() -> Self {
        Self {
            addr: None,
            pollee: Pollee::new(),
        }
    }

    /// Binds this socket to the given address.
    fn bind(&mut self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        if self.addr.is_some() && !addr.is_unnamed() {
            return Err(Errno::EINVAL);
        }
        if self.addr.is_none() {
            let bound_addr = addr.bind(task, true)?;
            self.addr = Some(bound_addr);
        }
        Ok(())
    }

    /// Transitions this socket to listening state.
    ///
    /// # Arguments
    ///
    /// * `backlog` - Maximum number of pending connections to queue
    fn listen(
        self,
        backlog: u16,
        global: &Arc<GlobalState>,
    ) -> Result<UnixListenStream, (Self, Errno)> {
        let Some(addr) = self.addr else {
            return Err((self, Errno::EINVAL));
        };
        let key = addr.to_key();
        let backlog = Arc::new(Backlog::new(addr, backlog, self.pollee));
        global
            .unix_addr_table
            .write()
            .insert(key, UnixEntry(UnixEntryInner::Stream(backlog.clone())));
        Ok(UnixListenStream {
            backlog,
            global: global.clone(),
        })
    }

    /// Converts this initial socket into a connected stream pair.
    fn into_connected(
        self,
        peer_addr: Arc<UnixBoundSocketAddr>,
    ) -> (UnixConnectedStream, UnixConnectedStream) {
        let UnixInitStream { addr, pollee } = self;
        UnixConnectedStream::new_pair(addr.map(Arc::new), Some(Arc::new(pollee)), Some(peer_addr))
    }
}

/// Connection backlog for a listening Unix socket.
///
/// Manages the queue of pending connections and the maximum backlog limit.
struct Backlog {
    /// The address this socket is listening on
    addr: Arc<UnixBoundSocketAddr>,
    /// Maximum number of pending connections
    limit: AtomicU16,
    /// Queue of pending connections (None when shut down)
    sockets: Mutex<crate::Platform, Option<VecDeque<UnixConnectedStream>>>,
    pollee: Pollee<crate::Platform>,
}

impl Backlog {
    fn new(addr: UnixBoundSocketAddr, backlog: u16, pollee: Pollee<crate::Platform>) -> Self {
        Self {
            addr: Arc::new(addr),
            limit: AtomicU16::new(backlog),
            sockets: litebox::sync::Mutex::new(Some(VecDeque::new())),
            pollee,
        }
    }

    /// Updates the maximum backlog size.
    fn set_backlog(&self, backlog: u16) {
        self.limit.store(backlog, Ordering::Relaxed);
    }

    /// Attempts to establish a connection without blocking.
    fn try_connect(
        &self,
        init: UnixInitStream,
    ) -> Result<UnixConnectedStream, (UnixInitStream, Errno)> {
        let mut sockets = self.sockets.lock();
        let Some(sockets) = &mut *sockets else {
            // the server socket is shutdown
            return Err((init, Errno::ECONNREFUSED));
        };

        let limit = self.limit.load(Ordering::Relaxed);
        if sockets.len() >= limit as usize {
            return Err((init, Errno::EAGAIN));
        }

        let (client, server) = init.into_connected(self.addr.clone());
        sockets.push_back(server);

        self.pollee.notify_observers(Events::IN);
        Ok(client)
    }

    /// Attempts to accept a pending connection without blocking.
    fn try_accept(&self) -> Result<UnixConnectedStream, TryOpError<Errno>> {
        let mut sockets = self.sockets.lock();
        let Some(sockets) = &mut *sockets else {
            // the server socket is shutdown
            return Err(TryOpError::Other(Errno::ECONNREFUSED));
        };

        match sockets.pop_front() {
            Some(stream) => {
                self.pollee.notify_observers(Events::OUT);
                Ok(stream)
            }
            None => Err(TryOpError::TryAgain),
        }
    }

    fn check_io_events(&self) -> Events {
        let sockets = self.sockets.lock();
        let Some(sockets) = &*sockets else {
            return Events::HUP;
        };
        let mut events = Events::empty();
        if !sockets.is_empty() {
            events |= Events::IN;
        }
        if sockets.len() < self.limit.load(Ordering::Relaxed) as usize {
            events |= Events::OUT;
        }
        events
    }

    /// Shuts down this backlog, preventing new connections.
    fn shutdown(&self) {
        let mut sockets = self.sockets.lock();
        *sockets = None;
    }
}

/// Represents a Unix stream socket in listening state.
struct UnixListenStream {
    backlog: Arc<Backlog>,
    global: Arc<GlobalState>,
}

impl UnixListenStream {
    /// Updates the maximum backlog size for pending connections.
    fn listen(&self, backlog: u16) {
        self.backlog.set_backlog(backlog);
    }

    fn register_observer(
        &self,
        observer: Weak<dyn litebox::event::observer::Observer<litebox::event::Events>>,
        mask: litebox::event::Events,
    ) {
        self.backlog.pollee.register_observer(observer, mask);
    }

    /// Returns the local address this socket is bound to.
    fn get_local_addr(&self) -> &UnixBoundSocketAddr {
        self.backlog.addr.as_ref()
    }
}

impl Drop for UnixListenStream {
    fn drop(&mut self) {
        self.backlog.shutdown();

        let key = self.backlog.addr.to_key();
        let mut table = self.global.unix_addr_table.write();
        // Only remove the entry if it still points to our backlog
        if let Some(UnixEntry(UnixEntryInner::Stream(backlog))) = table.get(&key)
            && Arc::ptr_eq(backlog, &self.backlog)
        {
            table.remove(&key);
        }
    }
}

/// Tracks the local and peer addresses for a connected socket.
struct AddrView {
    addr: Option<Arc<UnixBoundSocketAddr>>,
    peer: Option<Arc<UnixBoundSocketAddr>>,
}

impl AddrView {
    /// Creates a pair of address views for two connected sockets.
    ///
    /// The local address of one becomes the peer address of the other.
    fn new_pair(
        addr: Option<Arc<UnixBoundSocketAddr>>,
        peer: Option<Arc<UnixBoundSocketAddr>>,
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

    /// Returns the local address, if available.
    fn get_local_addr(&self) -> Option<&UnixBoundSocketAddr> {
        self.addr.as_deref()
    }

    /// Returns the peer address, if available.
    fn get_peer_addr(&self) -> Option<&UnixBoundSocketAddr> {
        self.peer.as_deref()
    }
}

/// A message sent over a Unix socket.
struct Message {
    data: Vec<u8>,
    // TODO: add control messages
    // cmsgs: Option<Vec<Cmsg>>,
}

/// Represents a connected Unix stream socket.
struct UnixConnectedStream {
    addr: AddrView,
    /// The read end of the local socket's channel for receiving messages.
    recv_channel: crate::channel::ReadEnd<Message>,
    /// The write end of the connected peer socket for sending messages.
    connected_send_channel: crate::channel::WriteEnd<Message>,
    pollee: Arc<Pollee<crate::Platform>>,
}

const UNIX_BUF_SIZE: usize = 65536;
impl UnixConnectedStream {
    /// Creates a pair of connected Unix stream sockets.
    fn new_pair(
        addr: Option<Arc<UnixBoundSocketAddr>>,
        pollee: Option<Arc<Pollee<crate::Platform>>>,
        peer: Option<Arc<UnixBoundSocketAddr>>,
    ) -> (Self, Self) {
        let (addr1, addr2) = AddrView::new_pair(addr, peer);
        let pollee1 = pollee.unwrap_or(Arc::new(Pollee::new()));
        let pollee2 = Arc::new(Pollee::new());
        let (send_channel, recv_channel) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee2.clone(), pollee1.clone()).split();
        let (send_channel_peer, recv_channel_peer) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee1.clone(), pollee2.clone()).split();
        (
            // Cross-wire: each socket keeps the other side's send channel.
            UnixConnectedStream {
                addr: addr1,
                recv_channel,
                connected_send_channel: send_channel_peer,
                pollee: pollee1,
            },
            UnixConnectedStream {
                addr: addr2,
                recv_channel: recv_channel_peer,
                connected_send_channel: send_channel,
                pollee: pollee2,
            },
        )
    }

    fn get_local_addr(&self) -> UnixSocketAddr {
        match self.addr.get_local_addr() {
            Some(addr) => UnixSocketAddr::from(addr),
            None => UnixSocketAddr::Unnamed,
        }
    }

    fn get_peer_addr(&self) -> UnixSocketAddr {
        match self.addr.get_peer_addr() {
            Some(addr) => UnixSocketAddr::from(addr),
            None => UnixSocketAddr::Unnamed,
        }
    }

    fn try_sendto(&self, msg: Message) -> Result<(), (Message, Errno)> {
        // TODO: write partial data?
        self.connected_send_channel.try_write_one(msg)
    }

    fn try_recvfrom(&self, mut buf: &mut [u8]) -> Result<usize, TryOpError<Errno>> {
        let mut total_read = 0;
        while !buf.is_empty() {
            let n = match self.recv_channel.peek_and_consume_one(|msg| {
                if buf.len() >= msg.data.len() {
                    buf[..msg.data.len()].copy_from_slice(&msg.data);
                    Ok((true, msg.data.len()))
                } else {
                    buf.copy_from_slice(&msg.data[..buf.len()]);
                    msg.data = msg.data.split_off(buf.len());
                    Ok((false, buf.len()))
                }
            }) {
                Ok(n) => n,
                Err(e) => {
                    if total_read > 0 {
                        break;
                    }
                    return match e {
                        Errno::EAGAIN => Err(TryOpError::TryAgain),
                        other => Err(TryOpError::Other(other)),
                    };
                }
            };
            total_read += n;
            buf = &mut buf[n..];
        }
        Ok(total_read)
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::empty();
        let is_read_shutdown = self.recv_channel.is_shutdown();
        let is_write_shutdown = self.connected_send_channel.is_shutdown();
        if is_read_shutdown {
            events |= Events::RDHUP | Events::IN;
            if is_write_shutdown {
                events |= Events::HUP;
            }
        }
        if !self.recv_channel.is_empty() {
            events |= Events::IN;
        }
        if !self.connected_send_channel.is_full() {
            events |= Events::OUT;
        }
        events
    }
}

enum UnixStreamState {
    Init(UnixInitStream),
    Listen(UnixListenStream),
    Connected(UnixConnectedStream),
}

impl UnixStreamState {
    fn connected(&self) -> Option<&UnixConnectedStream> {
        match self {
            UnixStreamState::Connected(conn) => Some(conn),
            _ => None,
        }
    }
    fn listen(&self) -> Option<&UnixListenStream> {
        match self {
            UnixStreamState::Listen(listen) => Some(listen),
            _ => None,
        }
    }
}

struct UnixStream {
    state: RwLock<crate::Platform, Option<UnixStreamState>>,
}

impl UnixStream {
    fn new(state: UnixStreamState) -> Self {
        Self {
            state: litebox::sync::RwLock::new(Some(state)),
        }
    }

    fn with_state_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&UnixStreamState) -> R,
    {
        let old = self.state.read();
        f(old.as_ref().expect("state should never be None"))
    }

    fn with_state_mut_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut UnixStreamState) -> R,
    {
        let mut old = self.state.write();
        f(old.as_mut().expect("state should never be None"))
    }

    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(UnixStreamState) -> (UnixStreamState, R),
    {
        let mut old = self.state.write();
        let (new, result) = f(old.take().expect("state should never be None"));
        *old = Some(new);
        result
    }

    fn bind(&self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.with_state_mut_ref(|state| {
            match state {
                UnixStreamState::Init(init) => init.bind(task, addr),
                UnixStreamState::Listen(_) => {
                    // Note Linux checks the given address and thus may return
                    // a different error code (e.g., EADDRINUSE).
                    Err(Errno::EINVAL)
                }
                UnixStreamState::Connected(_) => Err(Errno::EISCONN),
            }
        })
    }

    fn listen(&self, backlog: u16, global: &Arc<GlobalState>) -> Result<(), Errno> {
        self.with_state(|state| {
            let ret = match state {
                UnixStreamState::Init(init) => {
                    return match init.listen(backlog, global) {
                        Ok(listen) => (UnixStreamState::Listen(listen), Ok(())),
                        Err((init, err)) => (UnixStreamState::Init(init), Err(err)),
                    };
                }
                UnixStreamState::Listen(ref listen) => {
                    listen.listen(backlog);
                    Ok(())
                }
                UnixStreamState::Connected(_) => Err(Errno::EISCONN),
            };
            (state, ret)
        })
    }

    fn lookup(&self, task: &Task, addr: &UnixSocketAddr) -> Result<Arc<Backlog>, Errno> {
        let guard = task.global.unix_addr_table.read();
        let Some(key) = addr.to_key() else {
            return Err(Errno::EINVAL);
        };
        let Some(entry) = guard.get(&key) else {
            return Err(Errno::ECONNREFUSED);
        };
        match &entry.0 {
            UnixEntryInner::Stream(backlog) => Ok(backlog.clone()),
            UnixEntryInner::Datagram(_) => Err(Errno::EPROTOTYPE),
        }
    }
    fn try_connect(&self, backlog: &Backlog) -> Result<(), TryOpError<Errno>> {
        self.with_state(|state| match state {
            UnixStreamState::Init(init) => match backlog.try_connect(init) {
                Ok(connected) => (UnixStreamState::Connected(connected), Ok(())),
                Err((init, err)) => (UnixStreamState::Init(init), Err(err)),
            },
            UnixStreamState::Listen(s) => (UnixStreamState::Listen(s), Err(Errno::EINVAL)),
            UnixStreamState::Connected(s) => (UnixStreamState::Connected(s), Err(Errno::EISCONN)),
        })
        .map_err(|err| match err {
            Errno::EAGAIN => TryOpError::TryAgain,
            other => TryOpError::Other(other),
        })
    }
    fn connect(
        &self,
        task: &Task,
        addr: UnixSocketAddr,
        is_nonblocking: bool,
    ) -> Result<(), Errno> {
        let backlog = self.lookup(task, &addr)?;
        // check if we can bind to the address
        let _ = addr.bind(task, false)?;
        task.wait_cx()
            .wait_on_events(
                is_nonblocking,
                Events::OUT,
                |observer, mask| {
                    backlog.pollee.register_observer(observer, mask);
                    Ok(())
                },
                || self.try_connect(&backlog),
            )
            .map_err(Errno::from)
    }

    fn accept(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        mut peer: Option<&mut UnixSocketAddr>,
        is_nonblocking: bool,
    ) -> Result<UnixSocketInner, Errno> {
        let backlog = self.with_state_ref(|state| -> Result<Arc<Backlog>, Errno> {
            let listen = state.listen().ok_or(Errno::EINVAL)?;
            Ok(listen.backlog.clone())
        })?;
        cx.wait_on_events(
            is_nonblocking,
            Events::IN,
            |observer, mask| {
                backlog.pollee.register_observer(observer, mask);
                Ok(())
            },
            || {
                let accepted = backlog.try_accept()?;
                if let Some(peer) = peer.as_deref_mut() {
                    *peer = accepted.get_peer_addr();
                }
                Ok(UnixSocketInner::Stream(UnixStream::new(
                    UnixStreamState::Connected(accepted),
                )))
            },
        )
        .map_err(Errno::from)
    }

    fn sendto(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        timeout: Option<Duration>,
        buf: &[u8],
        is_nonblocking: bool,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let mut msg = Some(Message { data: buf.to_vec() });
        cx.with_timeout(timeout)
            .wait_on_events(
                is_nonblocking,
                Events::OUT,
                |observer, mask| {
                    self.with_state_ref(|state| {
                        let conn = state.connected().ok_or(Errno::ENOTCONN)?;
                        conn.pollee.register_observer(observer, mask);
                        Ok(())
                    })
                },
                || {
                    self.with_state_ref(|state| {
                        let conn = state
                            .connected()
                            .ok_or(TryOpError::Other(Errno::ENOTCONN))?;
                        if addr.is_some() {
                            return Err(TryOpError::Other(Errno::EISCONN));
                        }
                        match conn.try_sendto(msg.take().unwrap()) {
                            Ok(()) => Ok(buf.len()),
                            Err((m, Errno::EAGAIN)) => {
                                let _ = msg.replace(m);
                                Err(TryOpError::TryAgain)
                            }
                            Err((_, err)) => Err(TryOpError::Other(err)),
                        }
                    })
                },
            )
            .map_err(Errno::from)
    }

    fn recvfrom(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        timeout: Option<Duration>,
        buf: &mut [u8],
        is_nonblocking: bool,
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<usize, Errno> {
        cx.with_timeout(timeout)
            .wait_on_events(
                is_nonblocking,
                Events::IN,
                |observer, mask| {
                    self.with_state_ref(|state| {
                        let conn = state.connected().ok_or(Errno::ENOTCONN)?;
                        conn.pollee.register_observer(observer, mask);
                        Ok(())
                    })
                },
                || {
                    self.with_state_ref(|state| {
                        let conn = state
                            .connected()
                            .ok_or(TryOpError::Other(Errno::ENOTCONN))?;
                        let n = conn.try_recvfrom(buf)?;
                        // For connected stream sockets, no need to return the source address
                        if let Some(source_addr) = source_addr.as_deref_mut() {
                            *source_addr = None;
                        }
                        Ok(n)
                    })
                },
            )
            .map_err(Errno::from)
    }

    fn get_local_addr(&self) -> UnixSocketAddr {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(init) => match &init.addr {
                Some(addr) => UnixSocketAddr::from(addr),
                None => UnixSocketAddr::Unnamed,
            },
            UnixStreamState::Listen(listen) => UnixSocketAddr::from(listen.get_local_addr()),
            UnixStreamState::Connected(connect) => connect.get_local_addr(),
        })
    }

    fn register_observer(
        &self,
        observer: Weak<dyn litebox::event::observer::Observer<Events>>,
        mask: Events,
    ) {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(init) => init.pollee.register_observer(observer, mask),
            UnixStreamState::Listen(listen) => listen.register_observer(observer, mask),
            UnixStreamState::Connected(connect) => {
                connect.pollee.register_observer(observer, mask);
            }
        });
    }
    fn check_io_events(&self) -> Events {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(_) => Events::OUT | Events::HUP,
            UnixStreamState::Listen(listen) => listen.backlog.check_io_events(),
            UnixStreamState::Connected(conn) => conn.check_io_events(),
        })
    }
}

/// A datagram message with source address information
#[derive(Clone)]
struct DatagramMessage {
    data: Vec<u8>,
    // TODO: add control messages
    // cmsgs: Option<Vec<Cmsg>>,
    source: UnixSocketAddr,
}

impl WriteEnd<DatagramMessage> {
    fn try_write(&self, msg: DatagramMessage) -> Result<(), (DatagramMessage, Errno)> {
        self.try_write_one(msg)
    }
    fn write(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        timeout: Option<Duration>,
        msg: DatagramMessage,
        is_nonblocking: bool,
    ) -> Result<(), Errno> {
        let mut msg = Some(msg);
        cx.with_timeout(timeout)
            .wait_on_events(
                is_nonblocking,
                Events::OUT,
                |observer, mask| {
                    self.register_observer(observer, mask);
                    Ok(())
                },
                || match self.try_write(msg.take().unwrap()) {
                    Ok(()) => Ok(()),
                    Err((m, Errno::EAGAIN)) => {
                        let _ = msg.replace(m);
                        Err(TryOpError::TryAgain)
                    }
                    Err((_, err)) => Err(TryOpError::Other(err)),
                },
            )
            .map_err(Errno::from)
    }
}
impl ReadEnd<DatagramMessage> {
    /// Attempts to read datagram messages without blocking.
    ///
    /// Reads multiple messages from the same source address until the buffer
    /// is full or a message from a different source is encountered.
    fn try_read(
        &self,
        mut buf: &mut [u8],
        source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<usize, TryOpError<Errno>> {
        let mut src = None;
        let mut total_read = 0;
        let mut stop = false;
        while !buf.is_empty() {
            let n = match self.peek_and_consume_one(|msg| {
                if src.as_ref().is_some_and(|addr| *addr != msg.source) {
                    stop = true;
                    return Ok((false, 0));
                }
                if src.is_none() {
                    src.replace(msg.source.clone());
                }
                if buf.len() >= msg.data.len() {
                    buf[..msg.data.len()].copy_from_slice(&msg.data);
                    Ok((true, msg.data.len()))
                } else {
                    buf.copy_from_slice(&msg.data[..buf.len()]);
                    msg.data = msg.data.split_off(buf.len());
                    Ok((false, buf.len()))
                }
            }) {
                Ok(0) if stop => break,
                Ok(n) => n,
                Err(e) => {
                    if total_read > 0 {
                        break;
                    }
                    return match e {
                        Errno::EAGAIN => Err(TryOpError::TryAgain),
                        other => Err(TryOpError::Other(other)),
                    };
                }
            };
            total_read += n;
            buf = &mut buf[n..];
        }
        if let (Some(src), Some(source_addr)) = (src, source_addr) {
            *source_addr = Some(src);
        }
        Ok(total_read)
    }
}

struct UnixDatagramInner {
    /// The local address this socket is bound to, if any.
    addr: Option<(UnixBoundSocketAddr, Arc<GlobalState>)>,
    /// The read end of the local socket's channel for receiving messages.
    /// Set when the socket is bound via `bind` or `new_pair`.
    recv_channel: Option<ReadEnd<DatagramMessage>>,
    /// The write end of the connected peer socket for sending messages.
    /// Set when the socket is connected via `connect` or `new_pair`.
    connected_send_channel: Option<WriteEnd<DatagramMessage>>,
    pollee: Arc<Pollee<crate::Platform>>,
}
/// Represents a Unix datagram socket.
struct UnixDatagram {
    inner: RwLock<crate::Platform, UnixDatagramInner>,
}

impl Drop for UnixDatagramInner {
    fn drop(&mut self) {
        if let Some((addr, global)) = self.addr.take() {
            let key = addr.to_key();
            let mut table = global.unix_addr_table.write();
            // Only remove the entry if it matches the current socket
            if let Some(UnixEntry(UnixEntryInner::Datagram(send_channel))) = table.get(&key)
                && let Some(recv_channel) = &self.recv_channel
                && send_channel.is_pair(recv_channel)
            {
                table.remove(&key);
            }
        }
    }
}

impl UnixDatagramInner {
    /// Binds this socket to the given address.
    fn bind(&mut self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        if self.addr.is_some() {
            return if addr.is_unnamed() {
                Ok(())
            } else {
                Err(Errno::EINVAL)
            };
        }

        let bound_addr = addr.bind(task, true)?;
        let key = bound_addr.to_key();
        // Registers the write end of the socket in the global address table so it
        // can receive messages sent to this address.
        let (send_channel, recv_channel) =
            Channel::new(UNIX_BUF_SIZE, Arc::new(Pollee::new()), self.pollee.clone()).split();
        let _ = task
            .global
            .unix_addr_table
            .write()
            .insert(key, UnixEntry(UnixEntryInner::Datagram(send_channel)));
        self.addr = Some((bound_addr, task.global.clone()));
        self.recv_channel = Some(recv_channel);
        Ok(())
    }
}

impl UnixDatagram {
    fn new() -> Self {
        Self {
            inner: RwLock::new(UnixDatagramInner {
                addr: None,
                recv_channel: None,
                connected_send_channel: None,
                pollee: Arc::new(Pollee::new()),
            }),
        }
    }

    fn new_pair() -> (UnixDatagram, UnixDatagram) {
        let pollee1 = Arc::new(Pollee::new());
        let pollee2 = Arc::new(Pollee::new());
        let (send_channel, recv_channel) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee2.clone(), pollee1.clone()).split();
        let (send_channel_peer, recv_channel_peer) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee1.clone(), pollee2.clone()).split();
        (
            // Cross-wire: each socket keeps the other side's send channel.
            UnixDatagram {
                inner: RwLock::new(UnixDatagramInner {
                    addr: None,
                    recv_channel: Some(recv_channel),
                    connected_send_channel: Some(send_channel_peer),
                    pollee: pollee1,
                }),
            },
            UnixDatagram {
                inner: RwLock::new(UnixDatagramInner {
                    addr: None,
                    recv_channel: Some(recv_channel_peer),
                    connected_send_channel: Some(send_channel),
                    pollee: pollee2,
                }),
            },
        )
    }

    /// Binds this socket to the given address.
    fn bind(&self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.inner.write().bind(task, addr)
    }

    /// Looks up a socket address and returns its write endpoint.
    fn lookup(
        &self,
        task: &Task,
        addr: UnixSocketAddr,
    ) -> Result<WriteEnd<DatagramMessage>, Errno> {
        let guard = task.global.unix_addr_table.read();
        let Some(key) = addr.to_key() else {
            return Err(Errno::EINVAL);
        };
        let Some(entry) = guard.get(&key) else {
            return Err(Errno::ECONNREFUSED);
        };
        // check if we can bind to the address
        let _ = addr.bind(task, false)?;
        match &entry.0 {
            UnixEntryInner::Stream(_) => Err(Errno::EPROTOTYPE),
            UnixEntryInner::Datagram(send_channel) => Ok(send_channel.clone()),
        }
    }

    /// Connects this socket to a default peer address.
    ///
    /// Subsequent sends without an address will use this peer.
    fn connect(&self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.inner.write().connected_send_channel = Some(self.lookup(task, addr)?);
        Ok(())
    }

    fn recvfrom(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        timeout: Option<Duration>,
        buf: &mut [u8],
        is_nonblocking: bool,
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<usize, Errno> {
        cx.with_timeout(timeout)
            .wait_on_events(
                is_nonblocking,
                Events::IN,
                |observer, mask| {
                    self.inner.read().pollee.register_observer(observer, mask);
                    Ok(())
                },
                || {
                    let guard = self.inner.read();
                    let Some(recv_channel) = &guard.recv_channel else {
                        return Err(TryOpError::Other(Errno::ENOTCONN));
                    };
                    recv_channel.try_read(buf, source_addr.as_deref_mut())
                },
            )
            .map_err(Errno::from)
    }

    // Sends data to the specified or connected peer.
    ///
    /// If `addr` is provided, sends to that address. Otherwise, uses the
    /// connected peer (set via `connect()`).
    fn sendto(
        &self,
        task: &Task,
        timeout: Option<Duration>,
        buf: &[u8],
        is_nonblocking: bool,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let source = self.get_local_addr();
        let send_channel = if let Some(addr) = addr {
            self.lookup(task, addr)?
        } else if let Some(connected_send_channel) = &self.inner.read().connected_send_channel {
            connected_send_channel.clone()
        } else {
            return Err(Errno::ENOTCONN);
        };
        send_channel.write(
            &task.wait_cx(),
            timeout,
            DatagramMessage {
                data: buf.to_vec(),
                source,
            },
            is_nonblocking,
        )?;
        Ok(buf.len())
    }

    fn get_local_addr(&self) -> UnixSocketAddr {
        if let Some((addr, _)) = &self.inner.read().addr {
            UnixSocketAddr::from(addr)
        } else {
            UnixSocketAddr::Unnamed
        }
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::empty();
        if let Some(recv_channel) = &self.inner.read().recv_channel {
            if recv_channel.is_shutdown() {
                events |= Events::IN | Events::RDHUP;
            } else if !recv_channel.is_empty() {
                events |= Events::IN;
            }
        }
        if let Some(connected_send_channel) = &self.inner.read().connected_send_channel {
            if !connected_send_channel.is_full() {
                events |= Events::OUT;
            }
        } else {
            // If not connected, allow to sendto any address?
            events |= Events::OUT;
        }
        events
    }
}

enum UnixSocketInner {
    Stream(UnixStream),
    Datagram(UnixDatagram),
}
pub(crate) struct UnixSocket {
    inner: UnixSocketInner,
    status: AtomicU32,
    options: Mutex<crate::Platform, SocketOptions>,
}

impl UnixSocket {
    fn new_with_inner(inner: UnixSocketInner, flags: SockFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
        Self {
            inner,
            status: AtomicU32::new(status.bits()),
            options: litebox::sync::Mutex::new(SocketOptions::default()),
        }
    }

    pub(super) fn new(sock_type: SockType, flags: SockFlags) -> Option<Self> {
        let inner = match sock_type {
            SockType::Stream => UnixSocketInner::Stream(UnixStream::new(UnixStreamState::Init(
                UnixInitStream::new(),
            ))),
            SockType::Datagram => UnixSocketInner::Datagram(UnixDatagram::new()),
            e => {
                log_unsupported!("Unsupported unix socket type: {:?}", e);
                return None;
            }
        };
        Some(Self::new_with_inner(inner, flags))
    }

    pub(super) fn bind(&self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.bind(task, addr),
            UnixSocketInner::Datagram(datagram) => datagram.bind(task, addr),
        }
    }

    pub(super) fn listen(&self, backlog: u16, global: &Arc<GlobalState>) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.listen(backlog, global),
            UnixSocketInner::Datagram(_) => Err(Errno::EOPNOTSUPP),
        }
    }

    pub(super) fn connect(&self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.connect(task, addr, self.get_status().contains(OFlags::NONBLOCK))
            }
            UnixSocketInner::Datagram(datagram) => datagram.connect(task, addr),
        }
    }

    pub(super) fn accept(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        flags: SockFlags,
        peer: Option<&mut UnixSocketAddr>,
    ) -> Result<UnixSocket, Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                let accepted = stream.accept(
                    cx,
                    peer,
                    self.get_status().contains(OFlags::NONBLOCK)
                        | flags.contains(SockFlags::NONBLOCK),
                )?;
                Ok(UnixSocket::new_with_inner(accepted, flags))
            }
            UnixSocketInner::Datagram(_) => Err(Errno::EOPNOTSUPP),
        }
    }

    pub(super) fn sendto(
        &self,
        task: &Task,
        buf: &[u8],
        flags: SendFlags,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let supported_flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported sendto flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let is_nonblocking =
            flags.contains(SendFlags::DONTWAIT) || self.get_status().contains(OFlags::NONBLOCK);
        let timeout = self.options.lock().send_timeout;
        let ret = match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.sendto(&task.wait_cx(), timeout, buf, is_nonblocking, addr)
            }
            UnixSocketInner::Datagram(datagram) => {
                datagram.sendto(task, timeout, buf, is_nonblocking, addr)
            }
        };
        if let Err(Errno::EPIPE) = ret
            && !flags.contains(SendFlags::NOSIGNAL)
        {
            // TODO: send SIGPIPE signal
            unimplemented!("send SIGPIPE on EPIPE");
        }
        ret
    }

    pub(super) fn recvfrom(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<usize, Errno> {
        let supported_flags = ReceiveFlags::DONTWAIT;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvfrom flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let is_nonblocking =
            flags.contains(ReceiveFlags::DONTWAIT) || self.get_status().contains(OFlags::NONBLOCK);
        let timeout = self.options.lock().recv_timeout;
        let ret = match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.recvfrom(cx, timeout, buf, is_nonblocking, source_addr)
            }
            UnixSocketInner::Datagram(datagram) => {
                datagram.recvfrom(cx, timeout, buf, is_nonblocking, source_addr)
            }
        };
        match ret {
            Err(Errno::ESHUTDOWN) => Ok(0),
            other => other,
        }
    }

    pub(super) fn get_local_addr(&self) -> UnixSocketAddr {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.get_local_addr(),
            UnixSocketInner::Datagram(datagram) => datagram.get_local_addr(),
        }
    }

    pub(super) fn new_connected_pair(
        ty: SockType,
        flags: SockFlags,
    ) -> Option<(UnixSocket, UnixSocket)> {
        match ty {
            SockType::Stream => {
                let (conn1, conn2) = UnixConnectedStream::new_pair(None, None, None);
                Some((
                    UnixSocket::new_with_inner(
                        UnixSocketInner::Stream(UnixStream::new(UnixStreamState::Connected(conn1))),
                        flags,
                    ),
                    UnixSocket::new_with_inner(
                        UnixSocketInner::Stream(UnixStream::new(UnixStreamState::Connected(conn2))),
                        flags,
                    ),
                ))
            }
            SockType::Datagram => {
                let (datagram1, datagram2) = UnixDatagram::new_pair();
                Some((
                    UnixSocket::new_with_inner(UnixSocketInner::Datagram(datagram1), flags),
                    UnixSocket::new_with_inner(UnixSocketInner::Datagram(datagram2), flags),
                ))
            }
            _ => None,
        }
    }

    pub(super) fn setsockopt(
        &self,
        optname: SocketOptionName,
        optval: ConstPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS => return Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(so) => match so {
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO => {
                    let duration = super::net::read_timeval_as_duration(optval, optlen)?;
                    let mut options = self.options.lock();
                    match so {
                        SocketOption::RCVTIMEO => options.recv_timeout = duration,
                        SocketOption::SNDTIMEO => options.send_timeout = duration,
                        _ => unreachable!(),
                    }
                }
                SocketOption::LINGER => todo!("setsockopt LINGER"),
                SocketOption::REUSEADDR => {
                    let val = super::net::read_from_user::<u32>(optval, optlen)?;
                    self.options.lock().reuse_address = val != 0;
                }
                SocketOption::KEEPALIVE => {
                    let val = super::net::read_from_user::<u32>(optval, optlen)?;
                    self.options.lock().keep_alive = val != 0;
                }
                // Don't allow changing socket type and credentials
                SocketOption::TYPE | SocketOption::PEERCRED => return Err(Errno::ENOPROTOOPT),
                // We use fixed buffer size for now
                SocketOption::RCVBUF | SocketOption::SNDBUF => return Err(Errno::EOPNOTSUPP),
                SocketOption::BROADCAST => todo!("setsockopt BROADCAST"),
            },
            SocketOptionName::TCP(_) => return Err(Errno::EINVAL),
        }
        Ok(())
    }
    pub(super) fn getsockopt(
        &self,
        optname: SocketOptionName,
        optval: MutPtr<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        let val: u32 = match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS => return Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::Socket(so) => match so {
                SocketOption::RCVTIMEO | SocketOption::SNDTIMEO | SocketOption::LINGER => {
                    return super::net::handle_timeval_sockopt(
                        || match so {
                            SocketOption::RCVTIMEO => self.options.lock().recv_timeout,
                            SocketOption::SNDTIMEO => self.options.lock().send_timeout,
                            SocketOption::LINGER => self.options.lock().linger_timeout,
                            _ => unreachable!(),
                        },
                        optval,
                        len,
                    );
                }
                SocketOption::REUSEADDR => u32::from(self.options.lock().reuse_address),
                SocketOption::TYPE => match self.inner {
                    UnixSocketInner::Stream(_) => SockType::Stream as u32,
                    UnixSocketInner::Datagram(_) => SockType::Datagram as u32,
                },
                SocketOption::KEEPALIVE => u32::from(self.options.lock().keep_alive),
                _ => todo!("getsockopt for {:?}", so),
            },
            SocketOptionName::TCP(_) => return Err(Errno::EINVAL),
        };
        super::net::write_u32_option(val, optval, len)
    }

    super::common_functions_for_file_status!();
}

impl IOPollable for UnixSocket {
    fn register_observer(
        &self,
        observer: Weak<dyn litebox::event::observer::Observer<Events>>,
        mask: Events,
    ) {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.register_observer(observer, mask);
            }
            UnixSocketInner::Datagram(datagram) => {
                datagram
                    .inner
                    .read()
                    .pollee
                    .register_observer(observer, mask);
            }
        }
    }

    fn check_io_events(&self) -> Events {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.check_io_events(),
            UnixSocketInner::Datagram(datagram) => datagram.check_io_events(),
        }
    }
}

pub(crate) struct UnixEntry(UnixEntryInner);
enum UnixEntryInner {
    Stream(Arc<Backlog>),
    Datagram(WriteEnd<DatagramMessage>),
}

/// Type alias for the global Unix socket address table.
pub(crate) type UnixAddrTable = BTreeMap<UnixSocketAddrKey, UnixEntry>;
