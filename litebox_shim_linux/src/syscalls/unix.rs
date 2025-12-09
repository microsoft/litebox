//! Unix domain socket implementation for the Linux shim layer.

use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

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
use litebox_common_linux::{ReceiveFlags, SendFlags, SockFlags, SockType, errno::Errno};

use crate::{
    FileFd, GlobalState, Task,
    channel::{Channel, ReadEnd, WriteEnd},
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

    /// Connects this socket to the given address.
    ///
    /// # Arguments
    ///
    /// * `task` - The current task context
    /// * `addr` - The address to connect to
    /// * `is_nonblocking` - Whether to use non-blocking mode
    fn connect(
        self,
        task: &Task,
        addr: UnixSocketAddr,
        is_nonblocking: bool,
    ) -> Result<UnixConnectedStream, (Self, Errno)> {
        let guard = task.global.unix_addr_table.read();
        let Some(key) = addr.to_key() else {
            return Err((self, Errno::EINVAL));
        };
        let Some(entry) = guard.get(&key) else {
            return Err((self, Errno::ECONNREFUSED));
        };
        // check if we can bind to the address
        if let Err(err) = addr.bind(task, false) {
            return Err((self, err));
        }
        match &entry.0 {
            UnixEntryInner::Stream(backlog) => {
                let backlog = backlog.clone();
                drop(guard);
                backlog.connect(self, is_nonblocking)
            }
            UnixEntryInner::Datagram(_) => Err((self, Errno::EPROTOTYPE)),
        }
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

    /// Establishes a connection, blocking if necessary.
    fn connect(
        &self,
        mut init: UnixInitStream,
        is_nonblocking: bool,
    ) -> Result<UnixConnectedStream, (UnixInitStream, Errno)> {
        if is_nonblocking {
            self.try_connect(init)
        } else {
            // TODO: use polling instead of busy loop
            loop {
                init = match self.try_connect(init) {
                    Ok(stream) => return Ok(stream),
                    Err((init, Errno::EAGAIN)) => init,
                    Err((init, err)) => return Err((init, err)),
                };
                core::hint::spin_loop();
            }
        }
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
        let limit = self.limit.load(Ordering::Relaxed);
        let sockets = self.sockets.lock();
        let Some(sockets) = &*sockets else {
            return Events::HUP;
        };
        let mut events = Events::empty();
        if !sockets.is_empty() {
            events |= Events::IN;
        }
        if sockets.len() < limit as usize {
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

    /// Accepts a pending connection.
    fn accept(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        is_nonblocking: bool,
    ) -> Result<UnixConnectedStream, Errno> {
        cx.wait_on_events(
            is_nonblocking,
            Events::IN,
            |observer, mask| {
                self.register_observer(observer, mask);
                Ok(())
            },
            || self.backlog.try_accept(),
        )
        .map_err(Errno::from)
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
    reader: crate::channel::ReadEnd<Message>,
    writer: crate::channel::WriteEnd<Message>,
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
        let (writer_peer, reader) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee2.clone(), pollee1.clone()).split();
        let (writer, reader_peer) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee1.clone(), pollee2.clone()).split();
        (
            UnixConnectedStream {
                addr: addr1,
                reader,
                writer,
                pollee: pollee1,
            },
            UnixConnectedStream {
                addr: addr2,
                reader: reader_peer,
                writer: writer_peer,
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
        self.writer.try_write_one(msg)
    }

    fn sendto(&self, buf: &[u8], is_nonblocking: bool) -> Result<usize, Errno> {
        let mut msg = Message { data: buf.to_vec() };
        if is_nonblocking {
            self.try_sendto(msg).map_err(|(_, err)| err)?;
            Ok(buf.len())
        } else {
            // TODO: use polling instead of busy loop
            loop {
                msg = match self.try_sendto(msg) {
                    Ok(()) => return Ok(buf.len()),
                    Err((msg, Errno::EAGAIN)) => msg,
                    Err((_, err)) => return Err(err),
                };
                core::hint::spin_loop();
            }
        }
    }

    fn try_recvfrom(&self, mut buf: &mut [u8]) -> Result<usize, TryOpError<Errno>> {
        let mut total_read = 0;
        while !buf.is_empty() {
            let n = match self.reader.peek_and_consume_one(|msg| {
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
        let is_read_shutdown = self.reader.is_shutdown();
        let is_write_shutdown = self.writer.is_shutdown();
        if is_read_shutdown {
            events |= Events::RDHUP | Events::IN;
            if is_write_shutdown {
                events |= Events::HUP;
            }
        }
        if !self.reader.is_empty() {
            events |= Events::IN;
        }
        if !self.writer.is_full() {
            events |= Events::OUT;
        }
        events
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
    fn write(&self, mut msg: DatagramMessage, is_nonblocking: bool) -> Result<(), Errno> {
        if is_nonblocking {
            self.try_write(msg).map_err(|(_, err)| err)?;
            Ok(())
        } else {
            // TODO: use polling instead of busy loop
            loop {
                msg = match self.try_write(msg) {
                    Ok(()) => return Ok(()),
                    Err((msg, Errno::EAGAIN)) => msg,
                    Err((_, err)) => return Err(err),
                }
            }
        }
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
    ) -> Result<usize, Errno> {
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
                    return Err(e);
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

/// Represents a Unix datagram socket.
struct UnixDatagram {
    /// The local address this socket is bound to, if any.
    addr: Option<(UnixBoundSocketAddr, Arc<GlobalState>)>,
    /// The read end of the local socket's channel.
    reader: Option<ReadEnd<DatagramMessage>>,
    /// The write end of the remote socket it is connected to, if any.
    peer_writer: Option<WriteEnd<DatagramMessage>>,
    pollee: Arc<Pollee<crate::Platform>>,
}

impl Drop for UnixDatagram {
    fn drop(&mut self) {
        if let Some((addr, global)) = self.addr.take() {
            let key = addr.to_key();
            let mut table = global.unix_addr_table.write();
            // Only remove the entry if it matches the current socket
            if let Some(UnixEntry(UnixEntryInner::Datagram(writer))) = table.get(&key)
                && let Some(reader) = &self.reader
                && writer.is_pair(reader)
            {
                table.remove(&key);
            }
        }
    }
}

impl Drop for UnixDatagram {
    fn drop(&mut self) {
        if let Some((addr, global)) = self.addr.take() {
            let key = addr.to_key();
            let mut table = global.unix_addr_table.write();
            // Only remove the entry if it matches the current socket
            if let Some(UnixEntry(UnixEntryInner::Datagram(writer))) = table.get(&key)
                && let Some(reader) = &self.reader
                && writer.is_pair(reader)
            {
                table.remove(&key);
            }
        }
    }
}

impl UnixDatagram {
    fn new() -> Self {
        Self {
            addr: None,
            reader: None,
            peer_writer: None,
            pollee: Arc::new(Pollee::new()),
        }
    }

    fn new_pair() -> (UnixDatagram, UnixDatagram) {
        let pollee1 = Arc::new(Pollee::new());
        let pollee2 = Arc::new(Pollee::new());
        let (writer_peer, reader) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee1.clone(), pollee2.clone()).split();
        let (writer, reader_peer) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee2.clone(), pollee1.clone()).split();
        (
            UnixDatagram {
                addr: None,
                reader: Some(reader),
                peer_writer: Some(writer),
                pollee: pollee2,
            },
            UnixDatagram {
                addr: None,
                reader: Some(reader_peer),
                peer_writer: Some(writer_peer),
                pollee: pollee1,
            },
        )
    }

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
        let (writer, reader) = Channel::new(UNIX_BUF_SIZE).split();
        let _ = task
            .global
            .unix_addr_table
            .write()
            .insert(key, UnixEntry(UnixEntryInner::Datagram(writer)));
        self.addr = Some((bound_addr, task.global.clone()));
        self.reader = Some(reader);
        Ok(())
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
            UnixEntryInner::Datagram(writer) => Ok(writer.clone()),
        }
    }

    /// Connects this socket to a default peer address.
    ///
    /// Subsequent sends without an address will use this peer.
    fn connect(&mut self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.peer_writer = Some(self.lookup(task, addr)?);
        Ok(())
    }

    // Sends data to the specified or connected peer.
    ///
    /// If `addr` is provided, sends to that address. Otherwise, uses the
    /// connected peer (set via `connect()`).
    fn sendto(
        &self,
        task: &Task,
        buf: &[u8],
        is_nonblocking: bool,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let source = self.get_local_addr();
        if let Some(addr) = addr {
            let peer_writer = self.lookup(task, addr)?;
            peer_writer.write(
                DatagramMessage {
                    data: buf.to_vec(),
                    source,
                },
                is_nonblocking,
            )?;
        } else if let Some(peer_writer) = &self.peer_writer {
            peer_writer.write(
                DatagramMessage {
                    data: buf.to_vec(),
                    source,
                },
                is_nonblocking,
            )?;
        } else {
            return Err(Errno::ENOTCONN);
        }
        Ok(buf.len())
    }

    /// Receives data from any sender.
    ///
    /// If `source_addr` is provided, it will be populated with the sender's address.
    fn recvfrom(
        &self,
        buf: &mut [u8],
        is_nonblocking: bool,
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<usize, Errno> {
        let Some(reader) = &self.reader else {
            return Err(Errno::ENOTCONN);
        };
        let ret = if is_nonblocking {
            reader.try_read(buf, source_addr.as_deref_mut())
        } else {
            // TODO: use polling instead of busy wait
            loop {
                match reader.try_read(buf, source_addr.as_deref_mut()) {
                    Ok(size) => break Ok(size),
                    Err(Errno::EAGAIN) => {}
                    Err(err) => break Err(err),
                }
                core::hint::spin_loop();
            }
        };
        match ret {
            Err(Errno::ESHUTDOWN) => Ok(0),
            other => other,
        }
    }

    fn get_local_addr(&self) -> UnixSocketAddr {
        if let Some((addr, _)) = &self.addr {
            UnixSocketAddr::from(addr)
        } else {
            UnixSocketAddr::Unnamed
        }
    }
}

enum UnixSocketState {
    InitStream(UnixInitStream),
    ListenStream(UnixListenStream),
    ConnectedStream(UnixConnectedStream),

    Datagram(UnixDatagram),
}

pub struct UnixSocket {
    state: RwLock<crate::Platform, Option<UnixSocketState>>,
    status: AtomicU32,
    // options: Mutex<crate::Platform, SocketOptions>,
}

impl UnixSocket {
    fn new_with_state(state: UnixSocketState, flags: SockFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
        Self {
            state: litebox::sync::RwLock::new(Some(state)),
            status: AtomicU32::new(status.bits()),
            // options: litebox::sync::Mutex::new(SocketOptions::default()),
        }
    }

    pub(super) fn new(sock_type: SockType, flags: SockFlags) -> Option<Self> {
        let state = match sock_type {
            SockType::Stream => UnixSocketState::InitStream(UnixInitStream::new()),
            SockType::Datagram => UnixSocketState::Datagram(UnixDatagram::new()),
            e => {
                log_unsupported!("Unsupported unix socket type: {:?}", e);
                return None;
            }
        };
        Some(Self::new_with_state(state, flags))
    }

    fn with_state_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&UnixSocketState) -> R,
    {
        let old = self.state.read();
        f(old.as_ref().expect("state should never be None"))
    }

    fn with_state_mut_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut UnixSocketState) -> R,
    {
        let mut old = self.state.write();
        f(old.as_mut().expect("state should never be None"))
    }

    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(UnixSocketState) -> (UnixSocketState, R),
    {
        let mut old = self.state.write();
        let (new, result) = f(old.take().expect("state should never be None"));
        *old = Some(new);
        result
    }

    pub(super) fn bind(&self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.with_state_mut_ref(|state| {
            match state {
                UnixSocketState::InitStream(init) => init.bind(task, addr),
                UnixSocketState::ListenStream(_) => {
                    // Note Linux checks the given address and thus may return
                    // a different error code (e.g., EADDRINUSE).
                    Err(Errno::EINVAL)
                }
                UnixSocketState::ConnectedStream(_) => Err(Errno::EISCONN),
                UnixSocketState::Datagram(unix) => unix.bind(task, addr),
            }
        })
    }

    pub(super) fn listen(&self, backlog: u16, global: &Arc<GlobalState>) -> Result<(), Errno> {
        self.with_state(|state| {
            let ret = match state {
                UnixSocketState::InitStream(init) => {
                    return match init.listen(backlog, global) {
                        Ok(listen) => (UnixSocketState::ListenStream(listen), Ok(())),
                        Err((init, err)) => (UnixSocketState::InitStream(init), Err(err)),
                    };
                }
                UnixSocketState::ListenStream(ref listen) => {
                    listen.listen(backlog);
                    Ok(())
                }
                UnixSocketState::ConnectedStream(_) => Err(Errno::EISCONN),
                UnixSocketState::Datagram(_) => Err(Errno::EOPNOTSUPP),
            };
            (state, ret)
        })
    }

    pub(super) fn connect(&self, task: &Task, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.with_state(|state| {
            let ret = match state {
                UnixSocketState::InitStream(init) => {
                    return match init.connect(
                        task,
                        addr,
                        self.get_status().contains(OFlags::NONBLOCK),
                    ) {
                        Ok(connected) => (UnixSocketState::ConnectedStream(connected), Ok(())),
                        Err((init, err)) => (UnixSocketState::InitStream(init), Err(err)),
                    };
                }
                UnixSocketState::ListenStream(_) => Err(Errno::EINVAL),
                UnixSocketState::ConnectedStream(_) => Err(Errno::EISCONN),
                UnixSocketState::Datagram(mut unix) => {
                    let ret = unix.connect(task, addr);
                    return (UnixSocketState::Datagram(unix), ret);
                }
            };
            (state, ret)
        })
    }

    pub(super) fn accept(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        flags: SockFlags,
        peer: Option<&mut UnixSocketAddr>,
    ) -> Result<UnixSocket, Errno> {
        self.with_state_ref(|state| match state {
            UnixSocketState::ListenStream(listen) => {
                let accepted = listen.accept(
                    cx,
                    self.get_status().contains(OFlags::NONBLOCK)
                        | flags.contains(SockFlags::NONBLOCK),
                )?;
                if let Some(peer) = peer {
                    *peer = accepted.get_peer_addr();
                }
                Ok(UnixSocket::new_with_state(
                    UnixSocketState::ConnectedStream(accepted),
                    flags,
                ))
            }
            UnixSocketState::InitStream(_) | UnixSocketState::ConnectedStream(_) => {
                Err(Errno::EINVAL)
            }
            UnixSocketState::Datagram(_) => Err(Errno::EOPNOTSUPP),
        })
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

        let ret = self.with_state_ref(|state| match state {
            UnixSocketState::InitStream(_) | UnixSocketState::ListenStream(_) => {
                Err(Errno::ENOTCONN)
            }
            UnixSocketState::ConnectedStream(connect) => {
                if addr.is_some() {
                    return Err(Errno::EISCONN);
                }
                connect.sendto(buf, is_nonblocking)
            }
            UnixSocketState::Datagram(sock) => sock.sendto(task, buf, is_nonblocking, addr),
        });
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

        let ret = self.with_state_ref(|state| match state {
            UnixSocketState::InitStream(_) | UnixSocketState::ListenStream(_) => Err(Errno::EINVAL),
            UnixSocketState::ConnectedStream(connect) => {
                if let Some(source_addr) = source_addr {
                    *source_addr = None;
                }
                cx.wait_on_events(
                    is_nonblocking,
                    Events::IN,
                    |observer, filter| {
                        self.register_observer(observer, filter);
                        Ok(())
                    },
                    || connect.try_recvfrom(buf),
                )
                .map_err(Errno::from)
            }
            UnixSocketState::Datagram(sock) => sock.recvfrom(buf, is_nonblocking, source_addr),
        });
        match ret {
            Err(Errno::ESHUTDOWN) => Ok(0),
            other => other,
        }
    }

    pub(super) fn get_local_addr(&self) -> UnixSocketAddr {
        self.with_state_ref(|state| match state {
            UnixSocketState::InitStream(init) => match &init.addr {
                Some(addr) => UnixSocketAddr::from(addr),
                None => UnixSocketAddr::Unnamed,
            },
            UnixSocketState::ListenStream(listen) => UnixSocketAddr::from(listen.get_local_addr()),
            UnixSocketState::ConnectedStream(connect) => connect.get_local_addr(),
            UnixSocketState::Datagram(sock) => sock.get_local_addr(),
        })
    }

    pub(super) fn new_connected_pair(
        ty: SockType,
        flags: SockFlags,
    ) -> Option<(UnixSocket, UnixSocket)> {
        match ty {
            SockType::Stream => {
                let (conn1, conn2) = UnixConnectedStream::new_pair(None, None, None);
                Some((
                    UnixSocket::new_with_state(UnixSocketState::ConnectedStream(conn1), flags),
                    UnixSocket::new_with_state(UnixSocketState::ConnectedStream(conn2), flags),
                ))
            }
            SockType::Datagram => {
                let (datagram1, datagram2) = UnixDatagram::new_pair();
                Some((
                    UnixSocket::new_with_state(UnixSocketState::Datagram(datagram1), flags),
                    UnixSocket::new_with_state(UnixSocketState::Datagram(datagram2), flags),
                ))
            }
            _ => None,
        }
    }

    super::common_functions_for_file_status!();
}

impl IOPollable for UnixSocket {
    fn register_observer(
        &self,
        observer: Weak<dyn litebox::event::observer::Observer<Events>>,
        mask: Events,
    ) {
        self.with_state_ref(|state| match state {
            UnixSocketState::InitStream(init) => init.pollee.register_observer(observer, mask),
            UnixSocketState::ListenStream(listen) => listen.register_observer(observer, mask),
            UnixSocketState::ConnectedStream(connect) => {
                connect.pollee.register_observer(observer, mask);
            }
            UnixSocketState::Datagram(sock) => sock.pollee.register_observer(observer, mask),
        });
    }

    fn check_io_events(&self) -> Events {
        self.with_state_ref(|state| match state {
            UnixSocketState::InitStream(_) => Events::OUT | Events::HUP,
            UnixSocketState::ListenStream(listen) => listen.backlog.check_io_events(),
            UnixSocketState::ConnectedStream(conn) => conn.check_io_events(),
            UnixSocketState::Datagram(_) => todo!(),
        })
    }
}

pub(crate) struct UnixEntry(UnixEntryInner);
enum UnixEntryInner {
    Stream(Arc<Backlog>),
    Datagram(WriteEnd<DatagramMessage>),
}

/// Type alias for the global Unix socket address table.
pub(crate) type UnixAddrTable = BTreeMap<UnixSocketAddrKey, UnixEntry>;
