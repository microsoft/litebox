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
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::{Mode, OFlags, errors::OpenError},
    sync::{Mutex, RwLock},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    IpOption, ReceiveFlags, SendFlags, SockFlags, SockType, SocketOption, SocketOptionName, Ucred,
    errno::Errno,
};

use crate::{
    ConstPtr, FileFd, GlobalState, MutPtr, ShimFS, Task,
    channel::{Channel, ReadEnd, WriteEnd},
    syscalls::net::{SocketOptionValue, SocketOptions},
};

pub(crate) struct UnixSocketSubsystem<FS: ShimFS>(core::marker::PhantomData<FS>);
impl<FS: ShimFS> FdEnabledSubsystem for UnixSocketSubsystem<FS> {
    type Entry = UnixSocket<FS>;
}
impl<FS: ShimFS> FdEnabledSubsystemEntry for UnixSocket<FS> {}

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
enum UnixBoundSocketAddr<FS: ShimFS> {
    Path((String, FileFd<FS>, Arc<FS>)),
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
    fn bind<FS: ShimFS>(
        self,
        task: &Task<FS>,
        is_server: bool,
    ) -> Result<UnixBoundSocketAddr<FS>, Errno> {
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
                    .files
                    .borrow()
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
                Ok(UnixBoundSocketAddr::Path((
                    path,
                    file,
                    task.files.borrow().fs.clone(),
                )))
            }
            UnixSocketAddr::Abstract(data) => {
                // TODO: check if the abstract address is already in use
                Ok(UnixBoundSocketAddr::Abstract(data))
            }
            UnixSocketAddr::Unnamed => {
                // Autobind: assign a unique abstract address. Linux uses a
                // 5-hex-digit counter (e.g., "\0/00001").
                static AUTOBIND_COUNTER: core::sync::atomic::AtomicU32 =
                    core::sync::atomic::AtomicU32::new(1);
                let id = AUTOBIND_COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                let name = alloc::format!("{id:05x}");
                Ok(UnixBoundSocketAddr::Abstract(name.into_bytes()))
            }
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

impl<FS: ShimFS> UnixBoundSocketAddr<FS> {
    /// Converts this bound address to a key for the global address table.
    fn to_key(&self) -> UnixSocketAddrKey {
        match self {
            Self::Path((path, ..)) => UnixSocketAddrKey::Path(path.clone()),
            Self::Abstract(addr) => UnixSocketAddrKey::Abstract(addr.clone()),
        }
    }
}

impl<FS: ShimFS> Drop for UnixBoundSocketAddr<FS> {
    fn drop(&mut self) {
        match self {
            Self::Path((_, file, fs)) => {
                let _ = fs.close(file);
            }
            Self::Abstract(_) => {}
        }
    }
}

impl<FS: ShimFS> From<&UnixBoundSocketAddr<FS>> for UnixSocketAddr {
    fn from(addr: &UnixBoundSocketAddr<FS>) -> Self {
        match addr {
            UnixBoundSocketAddr::Path((path, ..)) => UnixSocketAddr::Path(path.clone()),
            UnixBoundSocketAddr::Abstract(data) => UnixSocketAddr::Abstract(data.clone()),
        }
    }
}

const UNCONNECTED_PEER_CRED: Ucred = Ucred {
    pid: 0,
    uid: u32::MAX,
    gid: u32::MAX,
};

/// Represents a Unix stream socket in its initial state.
///
/// This is the state immediately after socket creation, before the socket
/// has been connected, or put into listening mode.
struct UnixInitStream<FS: ShimFS> {
    /// Optional bound address for this socket
    addr: Option<UnixBoundSocketAddr<FS>>,
    pollee: Pollee<crate::Platform>,
}

impl<FS: ShimFS> UnixInitStream<FS> {
    fn new() -> Self {
        Self {
            addr: None,
            pollee: Pollee::new(),
        }
    }

    /// Binds this socket to the given address.
    fn bind(&mut self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
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
        global: &Arc<GlobalState<FS>>,
        listener_cred: Ucred,
    ) -> Result<UnixListenStream<FS>, (Self, Errno)> {
        let Some(addr) = self.addr else {
            return Err((self, Errno::EINVAL));
        };
        let key = addr.to_key();
        {
            let msg = alloc::format!(
                "UNIX LISTEN: key={:?} table_size={}\n",
                key,
                global.unix_addr_table.read().len(),
            );
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&msg);
        }
        let backlog = Arc::new(Backlog::new(addr, backlog, self.pollee, listener_cred));
        global
            .unix_addr_table
            .write()
            .insert(key, UnixEntry(UnixEntryInner::Stream(backlog.clone())));
        Ok(UnixListenStream {
            backlog,
            global: global.clone(),
            tcp_port: 0,
            tcp_raw_fd: None,
            tcp_proxy: None,
            _tcp_bridge: None,
        })
    }

    /// Converts this initial socket into a connected stream pair.
    fn into_connected(
        self,
        peer_addr: Arc<UnixBoundSocketAddr<FS>>,
        self_cred: Ucred,
        peer_cred: Ucred,
    ) -> (UnixConnectedStream<FS>, UnixConnectedStream<FS>) {
        let UnixInitStream { addr, pollee } = self;
        UnixConnectedStream::new_pair(
            addr.map(Arc::new),
            Some(Arc::new(pollee)),
            Some(peer_addr),
            self_cred,
            peer_cred,
        )
    }
}

/// Connection backlog for a listening Unix socket.
///
/// Manages the queue of pending connections and the maximum backlog limit.
struct Backlog<FS: ShimFS> {
    /// The address this socket is listening on
    addr: Arc<UnixBoundSocketAddr<FS>>,
    /// Maximum number of pending connections
    limit: AtomicU16,
    /// Credentials exposed to peers that connect to this listener.
    listener_cred: Ucred,
    /// Queue of pending connections (None when shut down)
    sockets: Mutex<crate::Platform, Option<VecDeque<UnixConnectedStream<FS>>>>,
    pollee: Pollee<crate::Platform>,
    /// Count of pending cross-worker TCP connections that haven't been
    /// accepted yet. Set by the bridge observer, checked by check_io_events.
    pending_tcp_connections: AtomicU32,
}

impl<FS: ShimFS> Backlog<FS> {
    fn new(
        addr: UnixBoundSocketAddr<FS>,
        backlog: u16,
        pollee: Pollee<crate::Platform>,
        listener_cred: Ucred,
    ) -> Self {
        Self {
            addr: Arc::new(addr),
            limit: AtomicU16::new(backlog),
            listener_cred,
            sockets: litebox::sync::Mutex::new(Some(VecDeque::new())),
            pollee,
            pending_tcp_connections: AtomicU32::new(0),
        }
    }

    /// Updates the maximum backlog size.
    fn set_backlog(&self, backlog: u16) {
        self.limit.store(backlog, Ordering::Relaxed);
    }

    /// Attempts to establish a connection without blocking.
    fn try_connect(
        &self,
        init: UnixInitStream<FS>,
        client_cred: Ucred,
    ) -> Result<UnixConnectedStream<FS>, (UnixInitStream<FS>, Errno)> {
        let mut sockets = self.sockets.lock();
        let Some(sockets) = &mut *sockets else {
            // the server socket is shutdown
            return Err((init, Errno::ECONNREFUSED));
        };

        let limit = self.limit.load(Ordering::Relaxed);
        if sockets.len() >= limit as usize {
            return Err((init, Errno::EAGAIN));
        }

        let (client, server) =
            init.into_connected(self.addr.clone(), client_cred, self.listener_cred);
        sockets.push_back(server);

        self.pollee.notify_observers(Events::IN);
        Ok(client)
    }

    /// Attempts to accept a pending connection without blocking.
    fn try_accept(&self) -> Result<UnixConnectedStream<FS>, TryOpError<Errno>> {
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
        let tcp_pending = self.pending_tcp_connections.load(Ordering::Relaxed);
        if !sockets.is_empty() || tcp_pending > 0 {
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
struct UnixListenStream<FS: ShimFS> {
    backlog: Arc<Backlog<FS>>,
    global: Arc<GlobalState<FS>>,
    /// TCP port allocated for cross-worker connections (0 = none).
    tcp_port: u16,
    /// Raw fd for the cross-worker TCP listener (if allocated).
    tcp_raw_fd: Option<u32>,
    /// TCP proxy for the cross-worker listener (for observer registration).
    tcp_proxy: Option<Arc<litebox::net::socket_channel::NetworkProxy<crate::Platform>>>,
    /// Bridge observer kept alive to forward TCP events to backlog pollee.
    _tcp_bridge: Option<Arc<BacklogTcpBridge<FS>>>,
}

impl<FS: ShimFS> UnixListenStream<FS> {
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
    fn get_local_addr(&self) -> &UnixBoundSocketAddr<FS> {
        self.backlog.addr.as_ref()
    }

    /// Allocate an internal TCP listener for cross-worker unix socket connections.
    ///
    /// Uses the guest syscall path (`do_socket`/`do_bind`/`do_listen`) so that
    /// TCP SYN packets are properly routed through the broker even when
    /// `platform_interaction = Manual`.
    /// Returns the allocated port number (0 on failure).
    fn start_tcp_listener(&mut self, global: &Arc<GlobalState<FS>>, task: &Task<FS>) -> u16 {
        use litebox::platform::DebugLogProvider as _;
        use litebox_common_linux::{AddressFamily, SockFlags, SockType};

        // Create TCP socket via guest syscall path.
        let raw_fd =
            match task.do_socket(AddressFamily::INET, SockType::Stream, SockFlags::empty(), 0) {
                Ok(fd) => fd,
                Err(e) => {
                    let msg = alloc::format!("UNIX TCP LISTENER: socket failed: {:?}\n", e);
                    litebox_platform_multiplex::platform().debug_log_print(&msg);
                    return 0;
                }
            };

        // Bind to ephemeral port (port 0 = kernel picks).
        let bind_addr = crate::syscalls::net::SocketAddress::Inet(core::net::SocketAddr::V4(
            core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0),
        ));
        if let Err(e) = task.do_bind(raw_fd, bind_addr) {
            let msg = alloc::format!("UNIX TCP LISTENER: bind failed: {:?}\n", e);
            litebox_platform_multiplex::platform().debug_log_print(&msg);
            return 0;
        }

        // Start listening.
        if let Err(e) = task.do_listen(raw_fd, 8) {
            let msg = alloc::format!("UNIX TCP LISTENER: listen failed: {:?}\n", e);
            litebox_platform_multiplex::platform().debug_log_print(&msg);
            return 0;
        }

        // Get the assigned port.
        let port = match task.do_getsockname_inet_port(raw_fd) {
            Some(p) if p != 0 => p,
            _ => return 0,
        };

        let msg = alloc::format!("UNIX TCP LISTENER: port={} started\n", port);
        litebox_platform_multiplex::platform().debug_log_print(&msg);

        // Get the proxy for the TCP socket.
        let tcp_proxy = match global.get_proxy_by_raw_fd(raw_fd, &task.files) {
            Some(p) => p,
            None => return 0,
        };

        // Register a bridge observer: when the TCP proxy fires IN events
        // (new connection ready), accept the TCP connection and push it into
        // the backlog directly from the network thread.
        {
            use litebox::event::IOPollable;
            let bridge = Arc::new(BacklogTcpBridge {
                backlog: self.backlog.clone(),
            });
            let bridge_weak =
                Arc::downgrade(&bridge) as Weak<dyn litebox::event::observer::Observer<Events>>;
            tcp_proxy.register_observer(bridge_weak, Events::IN);
            self._tcp_bridge = Some(bridge);
        }

        self.tcp_port = port;
        self.tcp_raw_fd = Some(raw_fd);
        self.tcp_proxy = Some(tcp_proxy);
        port
    }

    /// Drain pending TCP connections from the internal TCP listener and push
    /// them into the unix socket backlog as TCP-backed connected streams.
    ///
    /// Note: With the guest syscall path, TCP accept is handled in
    /// `UnixStream::accept()` using `task.do_accept()`. This method is
    /// retained for potential future use.
    fn drain_tcp_to_backlog(&self) {
        // TCP accept is now done via guest syscall path in UnixStream::accept().
    }
}

impl<FS: ShimFS> Drop for UnixListenStream<FS> {
    fn drop(&mut self) {
        self.backlog.shutdown();

        // Clean up sidecar metadata file.
        if let UnixBoundSocketAddr::Path((path, _, fs)) = self.backlog.addr.as_ref() {
            remove_sidecar(fs.as_ref(), path.as_str());
        }

        // The internal TCP listener raw fd is cleaned up when the process
        // exits (it lives in the guest fd table managed by do_socket).

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
struct AddrView<FS: ShimFS> {
    addr: Option<Arc<UnixBoundSocketAddr<FS>>>,
    peer: Option<Arc<UnixBoundSocketAddr<FS>>>,
}

impl<FS: ShimFS> AddrView<FS> {
    /// Creates a pair of address views for two connected sockets.
    ///
    /// The local address of one becomes the peer address of the other.
    fn new_pair(
        addr: Option<Arc<UnixBoundSocketAddr<FS>>>,
        peer: Option<Arc<UnixBoundSocketAddr<FS>>>,
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
    fn get_local_addr(&self) -> Option<&UnixBoundSocketAddr<FS>> {
        self.addr.as_deref()
    }

    /// Returns the peer address, if available.
    fn get_peer_addr(&self) -> Option<&UnixBoundSocketAddr<FS>> {
        self.peer.as_deref()
    }
}

/// Re-export for use by sibling modules (e.g. `net.rs`).
pub(super) use litebox::fd::PassedFd;

/// A message sent over a Unix socket.
pub(crate) struct Message {
    pub(crate) data: Vec<u8>,
    /// File descriptors passed via `SCM_RIGHTS` ancillary data.
    pub(crate) passed_fds: Vec<PassedFd>,
}

/// Represents a connected Unix stream socket.
struct UnixConnectedStream<FS: ShimFS> {
    addr: AddrView<FS>,
    transport: UnixTransport,
    peer_cred: Ucred,
    pollee: Arc<Pollee<crate::Platform>>,
}

/// Data transport for a connected unix socket.
///
/// Same-worker connections use in-memory channels (fast, zero-copy).
/// Cross-worker connections use a TCP stream through the broker's smoltcp
/// proxy, discovered via a sidecar metadata file on the shared filesystem.
enum UnixTransport {
    /// Same-worker: in-memory ring-buffer channels.
    Channel {
        recv: crate::channel::ReadEnd<Message>,
        send: crate::channel::WriteEnd<Message>,
    },
    /// Cross-worker: TCP-backed stream through broker/smoltcp.
    Tcp {
        proxy: Arc<litebox::net::socket_channel::NetworkProxy<crate::Platform>>,
    },
}

const UNIX_BUF_SIZE: usize = 65536;
impl<FS: ShimFS> UnixConnectedStream<FS> {
    /// Returns a pair identifier shared by both ends of a connected pair.
    ///
    /// Both peers produce the same value because the channels are
    /// cross-wired:
    ///
    ///   Socket A: recv = ReadEnd(EP_R1),  send = WriteEnd(_, peer→EP_R2)
    ///   Socket B: recv = ReadEnd(EP_R2),  send = WriteEnd(_, peer→EP_R1)
    ///
    ///   A: min(ptr(EP_R1), ptr(EP_R2)) = min(R1, R2)
    ///   B: min(ptr(EP_R2), ptr(EP_R1)) = min(R1, R2)  ✓
    ///
    /// Stable across `clone_for_fork` because both clones share the same
    /// underlying `Arc` allocations.
    pub(crate) fn socket_pair_id(&self) -> usize {
        match &self.transport {
            UnixTransport::Channel { recv, send } => {
                let recv_ptr = recv.endpoint_ptr() as usize;
                let send_peer_ptr = send.peer_ptr() as usize;
                core::cmp::min(recv_ptr, send_peer_ptr)
            }
            UnixTransport::Tcp { proxy } => Arc::as_ptr(proxy) as usize,
        }
    }

    /// Creates a pair of connected Unix stream sockets.
    fn new_pair(
        addr: Option<Arc<UnixBoundSocketAddr<FS>>>,
        pollee: Option<Arc<Pollee<crate::Platform>>>,
        peer: Option<Arc<UnixBoundSocketAddr<FS>>>,
        first_cred: Ucred,
        second_cred: Ucred,
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
                transport: UnixTransport::Channel {
                    recv: recv_channel,
                    send: send_channel_peer,
                },
                peer_cred: second_cred,
                pollee: pollee1,
            },
            UnixConnectedStream {
                addr: addr2,
                transport: UnixTransport::Channel {
                    recv: recv_channel_peer,
                    send: send_channel,
                },
                peer_cred: first_cred,
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

    fn peer_cred(&self) -> Ucred {
        self.peer_cred
    }

    fn try_sendto(&self, msg: Message) -> Result<(), (Message, Errno)> {
        match &self.transport {
            UnixTransport::Channel { send, .. } => {
                // TODO: write partial data?
                send.try_write_one(msg)
            }
            UnixTransport::Tcp { proxy } => {
                use litebox::net::socket_channel::NetworkProxy;
                match proxy.as_ref() {
                    NetworkProxy::Stream(stream) => match stream.try_write(&msg.data) {
                        Ok(_n) => Ok(()),
                        Err(_) => Err((msg, Errno::EPIPE)),
                    },
                    _ => Err((msg, Errno::EINVAL)),
                }
            }
        }
    }

    fn try_recvfrom(
        &self,
        mut buf: &mut [u8],
        seqpacket: bool,
        received_fds: &mut Vec<PassedFd>,
    ) -> Result<usize, TryOpError<Errno>> {
        match &self.transport {
            UnixTransport::Tcp { proxy } => {
                use litebox::net::socket_channel::NetworkProxy;
                match proxy.as_ref() {
                    NetworkProxy::Stream(stream) => {
                        match stream.try_read(buf, litebox::net::ReceiveFlags::empty(), None) {
                            Ok(n) => Ok(n),
                            Err(litebox::net::errors::ReceiveError::SocketInInvalidState) => {
                                Err(TryOpError::TryAgain)
                            }
                            Err(_) => Err(TryOpError::Other(Errno::ECONNRESET)),
                        }
                    }
                    _ => Err(TryOpError::Other(Errno::EINVAL)),
                }
            }
            UnixTransport::Channel { recv, .. } => {
                self.try_recvfrom_channel(recv, buf, seqpacket, received_fds)
            }
        }
    }

    fn try_recvfrom_channel(
        &self,
        recv: &crate::channel::ReadEnd<Message>,
        mut buf: &mut [u8],
        seqpacket: bool,
        received_fds: &mut Vec<PassedFd>,
    ) -> Result<usize, TryOpError<Errno>> {
        if seqpacket {
            // SOCK_SEQPACKET: return exactly one message per recv call.
            // If the buffer is smaller than the message, truncate (the
            // remainder is discarded, matching Linux semantics without
            // MSG_TRUNC).
            return recv
                .peek_and_consume_one(|msg| {
                    let copy_len = buf.len().min(msg.data.len());
                    buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                    received_fds.append(&mut msg.passed_fds);
                    Ok((true, copy_len))
                })
                .map_err(|e| match e {
                    Errno::EAGAIN => TryOpError::TryAgain,
                    other => TryOpError::Other(other),
                });
        }

        // SOCK_STREAM: coalesce reads across messages, allow partial
        // message consumption.
        let mut total_read = 0;
        while !buf.is_empty() {
            let n = match recv.peek_and_consume_one(|msg| {
                // Extract any passed fds from the first message that carries them.
                if !msg.passed_fds.is_empty() {
                    received_fds.append(&mut msg.passed_fds);
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
            if n == 0 {
                continue;
            }
            total_read += n;
            buf = &mut buf[n..];
        }
        Ok(total_read)
    }

    fn check_io_events(&self) -> Events {
        match &self.transport {
            UnixTransport::Tcp { proxy } => proxy.check_io_events(),
            UnixTransport::Channel { recv, send } => {
                let mut events = Events::empty();
                let is_read_shutdown = recv.is_shutdown();
                let is_write_shutdown = send.is_shutdown();
                let recv_peer_closed = recv.is_peer_shutdown();
                let send_peer_closed = send.is_peer_shutdown();

                if is_read_shutdown || recv_peer_closed {
                    events |= Events::RDHUP | Events::IN;
                    if is_write_shutdown || send_peer_closed {
                        events |= Events::HUP;
                    }
                }
                if !recv.is_empty() {
                    events |= Events::IN;
                }
                if !send_peer_closed && !send.is_full() {
                    events |= Events::OUT;
                }
                events
            }
        }
    }
}

enum UnixStreamState<FS: ShimFS> {
    Init(UnixInitStream<FS>),
    Listen(UnixListenStream<FS>),
    Connected(UnixConnectedStream<FS>),
}

impl<FS: ShimFS> UnixStreamState<FS> {
    fn connected(&self) -> Option<&UnixConnectedStream<FS>> {
        match self {
            UnixStreamState::Connected(conn) => Some(conn),
            _ => None,
        }
    }
    fn listen(&self) -> Option<&UnixListenStream<FS>> {
        match self {
            UnixStreamState::Listen(listen) => Some(listen),
            _ => None,
        }
    }
}

struct UnixStream<FS: ShimFS> {
    state: RwLock<crate::Platform, Option<UnixStreamState<FS>>>,
}

impl<FS: ShimFS> UnixStream<FS> {
    fn new(state: UnixStreamState<FS>) -> Self {
        Self {
            state: litebox::sync::RwLock::new(Some(state)),
        }
    }

    fn with_state_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&UnixStreamState<FS>) -> R,
    {
        let old = self.state.read();
        f(old.as_ref().expect("state should never be None"))
    }

    fn with_state_mut_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut UnixStreamState<FS>) -> R,
    {
        let mut old = self.state.write();
        f(old.as_mut().expect("state should never be None"))
    }

    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(UnixStreamState<FS>) -> (UnixStreamState<FS>, R),
    {
        let mut old = self.state.write();
        let (new, result) = f(old.take().expect("state should never be None"));
        *old = Some(new);
        result
    }

    fn bind(&self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
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

    fn listen(
        &self,
        task: &Task<FS>,
        backlog: u16,
        global: &Arc<GlobalState<FS>>,
    ) -> Result<(), Errno> {
        self.with_state(|state| {
            let ret = match state {
                UnixStreamState::Init(init) => {
                    // Extract the socket path before consuming init (for sidecar).
                    let sock_path = init.addr.as_ref().and_then(|a| match a {
                        UnixBoundSocketAddr::Path((p, ..)) => Some(p.clone()),
                        _ => None,
                    });

                    return match init.listen(backlog, global, task.current_ucred()) {
                        Ok(mut listen) => {
                            if let Some(path) = sock_path {
                                let fs = task.files.borrow().fs.clone();
                                let tcp_port = listen.start_tcp_listener(global, task);
                                if tcp_port != 0 {
                                    write_sidecar(fs.as_ref(), path.as_str(), tcp_port);
                                    // Log: sidecar write with port, raw_fd, path
                                    let diag = alloc::format!(
                                        "SIDECAR WRITE: path={} port={} raw_fd={:?} pid={}\n",
                                        path, tcp_port, listen.tcp_raw_fd, task.process_id.0,
                                    );
                                    if let Ok(f) = fs.open("/tmp/unix-port-trace.log", OFlags::CREAT | OFlags::RDWR | OFlags::APPEND, Mode::RWXU) {
                                        let _ = fs.write(&f, diag.as_bytes(), None);
                                        let _ = fs.close(&f);
                                    }
                                }
                            }
                            (UnixStreamState::Listen(listen), Ok(()))
                        }
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

    fn lookup(&self, task: &Task<FS>, addr: &UnixSocketAddr) -> Result<Arc<Backlog<FS>>, Errno> {
        let guard = task.global.unix_addr_table.read();
        let Some(key) = addr.to_key() else {
            return Err(Errno::EINVAL);
        };
        let Some(entry) = guard.get(&key) else {
            let table_keys: alloc::vec::Vec<_> = guard.keys().collect();
            let msg = alloc::format!(
                "UNIX CONNECT REFUSED: path={:?} table_size={} keys={:?} pid={}\n",
                key,
                guard.len(),
                table_keys,
                task.process_id.0,
            );
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&msg);
            return Err(Errno::ECONNREFUSED);
        };
        match &entry.0 {
            UnixEntryInner::Stream(backlog) => Ok(backlog.clone()),
            UnixEntryInner::Datagram(_) => Err(Errno::EPROTOTYPE),
        }
    }
    fn try_connect(
        &self,
        backlog: &Backlog<FS>,
        client_cred: Ucred,
    ) -> Result<(), TryOpError<Errno>> {
        self.with_state(|state| match state {
            UnixStreamState::Init(init) => match backlog.try_connect(init, client_cred) {
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
        task: &Task<FS>,
        addr: UnixSocketAddr,
        is_nonblocking: bool,
    ) -> Result<(), Errno> {
        match self.lookup(task, &addr) {
            Ok(backlog) => {
                // Same-worker: connect via in-memory backlog.
                let _ = addr.bind(task, false)?;
                task.wait_cx()
                    .wait_on_events(
                        is_nonblocking,
                        Events::OUT,
                        |observer, mask| {
                            backlog.pollee.register_observer(observer, mask);
                            Ok(())
                        },
                        || self.try_connect(&backlog, task.current_ucred()),
                    )
                    .map_err(Errno::from)
            }
            Err(Errno::ECONNREFUSED) => {
                // Local lookup failed — try cross-worker path via sidecar file.
                self.try_connect_remote(task, &addr, is_nonblocking)
            }
            Err(e) => Err(e),
        }
    }

    /// Attempt a cross-worker unix socket connection by reading the sidecar
    /// metadata file and establishing a TCP connection through the broker.
    fn try_connect_remote(
        &self,
        task: &Task<FS>,
        addr: &UnixSocketAddr,
        is_nonblocking: bool,
    ) -> Result<(), Errno> {
        let sock_path = match addr {
            UnixSocketAddr::Path(p) => p.clone(),
            _ => return Err(Errno::ECONNREFUSED),
        };

        let fs = task.files.borrow().fs.clone();
        let tcp_port = read_sidecar(fs.as_ref(), sock_path.as_str()).ok_or_else(|| {
            use litebox::platform::DebugLogProvider as _;
            let msg = alloc::format!(
                "UNIX CONNECT REFUSED (no sidecar): path={:?} pid={}\n",
                sock_path,
                task.process_id.0,
            );
            litebox_platform_multiplex::platform().debug_log_print(&msg);
            Errno::ECONNREFUSED
        })?;

        use litebox::platform::DebugLogProvider as _;
        let msg = alloc::format!(
            "UNIX CROSS-WORKER CONNECT: path={:?} tcp_port={} pid={}\n",
            sock_path,
            tcp_port,
            task.process_id.0,
        );
        litebox_platform_multiplex::platform().debug_log_print(&msg);

        // Create an internal TCP socket and connect through the guest syscall
        // path so the SYN goes through the broker's port router.
        let tcp_raw_fd = task
            .do_socket(
                litebox_common_linux::AddressFamily::INET,
                SockType::Stream,
                SockFlags::empty(),
                0,
            )
            .map_err(|_| Errno::ENOMEM)?;

        // Write diagnostic BEFORE connect.
        {
            let diag = alloc::format!(
                "CONNECT: path={:?} sidecar_port={} tcp_raw_fd={} pid={}\n",
                sock_path, tcp_port, tcp_raw_fd, task.process_id.0,
            );
            if let Ok(f) = fs.open("/tmp/unix-port-trace.log", OFlags::CREAT | OFlags::RDWR | OFlags::APPEND, Mode::RWXU) {
                let _ = fs.write(&f, diag.as_bytes(), None);
                let _ = fs.close(&f);
            }
        }

        let connect_addr = super::net::SocketAddress::Inet(core::net::SocketAddr::V4(
            core::net::SocketAddrV4::new(core::net::Ipv4Addr::LOCALHOST, tcp_port),
        ));
        let connect_result = task.do_connect(tcp_raw_fd, connect_addr);

        // Write diagnostic AFTER connect.
        {
            let diag = alloc::format!(
                "CONNECT RESULT: sidecar_port={} result={:?} pid={}\n",
                tcp_port, connect_result, task.process_id.0,
            );
            if let Ok(f) = fs.open("/tmp/unix-port-trace.log", OFlags::CREAT | OFlags::RDWR | OFlags::APPEND, Mode::RWXU) {
                let _ = fs.write(&f, diag.as_bytes(), None);
                let _ = fs.close(&f);
            }
        }

        connect_result?;

        // Get the proxy for the connected TCP socket.
        let proxy = task.files.borrow().with_socket(
            &task.global,
            tcp_raw_fd,
            |fd| task.global.get_proxy(fd),
            |_| Err(Errno::EINVAL),
        )?;

        // Wrap the TCP proxy in a unix-socket connected stream.
        let peer_addr = UnixBoundSocketAddr::Path((
            sock_path,
            // We don't have the actual file fd for the remote socket, use a
            // dummy open so AddrView can report the path.
            {
                let f = fs
                    .open("/dev/null", OFlags::RDONLY, Mode::empty())
                    .map_err(|_| Errno::ECONNREFUSED)?;
                f
            },
            fs,
        ));

        self.with_state(|state| match state {
            UnixStreamState::Init(init) => {
                let connected = UnixConnectedStream {
                    addr: AddrView {
                        addr: init.addr.map(Arc::new),
                        peer: Some(Arc::new(peer_addr)),
                    },
                    transport: UnixTransport::Tcp { proxy },
                    peer_cred: task.current_ucred(),
                    pollee: Arc::new(Pollee::new()),
                };
                (UnixStreamState::Connected(connected), Ok(()))
            }
            other => (other, Err(Errno::EISCONN)),
        })
    }

    fn accept(
        &self,
        task: Option<&Task<FS>>,
        cx: &WaitContext<'_, crate::Platform>,
        mut peer: Option<&mut UnixSocketAddr>,
        is_nonblocking: bool,
    ) -> Result<UnixSocketInner<FS>, Errno> {
        // Diagnostic: unconditional log to see if accept() is called at all.
        {
            let has_task = task.is_some();
            self.with_state_ref(|state| {
                if let Some(listen) = state.listen() {
                    if let UnixBoundSocketAddr::Path((ref path, _, ref fs)) = *listen.backlog.addr {
                        let bridge_fires = super::unix::bridge_fire_count();
                        let diag = alloc::format!(
                            "ACCEPT ENTRY: path={} has_task={} tcp_port={} bridge_fires={}\n",
                            path, has_task, listen.tcp_port, bridge_fires,
                        );
                        if let Ok(f) = fs.open("/tmp/unix-port-trace.log", OFlags::CREAT | OFlags::RDWR | OFlags::APPEND, Mode::RWXU) {
                            let _ = fs.write(&f, diag.as_bytes(), None);
                            let _ = fs.close(&f);
                        }
                    }
                }
            });
        }

        let (backlog, tcp_proxy) = self.with_state_ref(|state| -> Result<_, Errno> {
            let listen = state.listen().ok_or(Errno::EINVAL)?;
            Ok((listen.backlog.clone(), listen.tcp_proxy.clone()))
        })?;

        // Diagnostic: log whether tcp_proxy is available for this accept.
        if let Some(task) = task {
            self.with_state_ref(|state| {
                if let Some(listen) = state.listen() {
                    if let UnixBoundSocketAddr::Path((ref path, _, ref fs)) = *listen.backlog.addr {
                        let diag = alloc::format!(
                            "ACCEPT SETUP: path={} tcp_proxy={} tcp_raw_fd={:?} tcp_port={}\n",
                            path, tcp_proxy.is_some(), listen.tcp_raw_fd, listen.tcp_port,
                        );
                        if let Ok(f) = fs.open("/tmp/unix-port-trace.log", OFlags::CREAT | OFlags::RDWR | OFlags::APPEND, Mode::RWXU) {
                            let _ = fs.write(&f, diag.as_bytes(), None);
                            let _ = fs.close(&f);
                        }
                    }
                }
            });
        }

        cx.wait_on_events(
            is_nonblocking,
            Events::IN,
            |observer, mask| {
                backlog.pollee.register_observer(observer.clone(), mask);
                // Also register on the TCP proxy so we wake when cross-worker
                // TCP connections complete the handshake.
                if let Some(ref proxy) = tcp_proxy {
                    use litebox::event::IOPollable;
                    proxy.register_observer(observer, mask);
                }
                Ok(())
            },
            || {
                // First try to accept from the local backlog (same-worker).
                match backlog.try_accept() {
                    Ok(accepted) => {
                        if let Some(peer) = peer.as_deref_mut() {
                            *peer = accepted.get_peer_addr();
                        }
                        return Ok(UnixSocketInner::Stream(UnixStream::new(
                            UnixStreamState::Connected(accepted),
                        )));
                    }
                    Err(TryOpError::TryAgain) => {}
                    Err(e) => return Err(e),
                }

                // Then try to accept from the internal TCP listener (cross-worker)
                // using the guest syscall path so TCP SYN packets reach the broker.
                if let Some(task) = task {
                    // Log the port being checked in accept.
                    self.with_state_ref(|state| {
                        if let Some(listen) = state.listen() {
                            if let (Some(raw_fd), port) = (listen.tcp_raw_fd, listen.tcp_port) {
                                if let UnixBoundSocketAddr::Path((ref path, _, ref fs)) = *listen.backlog.addr {
                                    let actual_port = task.do_getsockname_inet_port(raw_fd);
                                    let diag = alloc::format!(
                                        "ACCEPT CHECK: path={} stored_port={} raw_fd={} actual_port={:?} pid={}\n",
                                        path, port, raw_fd, actual_port, task.process_id.0,
                                    );
                                    if let Ok(f) = fs.open("/tmp/unix-port-trace.log", OFlags::CREAT | OFlags::RDWR | OFlags::APPEND, Mode::RWXU) {
                                        let _ = fs.write(&f, diag.as_bytes(), None);
                                        let _ = fs.close(&f);
                                    }
                                }
                            }
                        }
                    });
                    let result = self.with_state_ref(|state| -> Option<UnixConnectedStream<FS>> {
                        let listen = state.listen()?;
                        let raw_fd = listen.tcp_raw_fd?;
                        let accepted_fd = match listen.global.try_accept_by_raw_fd(raw_fd, &task.files) {
                            Ok(fd) => fd,
                            Err(e) => {
                                // Log the error for diagnostics.
                                if let UnixBoundSocketAddr::Path((ref path, _, ref fs)) = *listen.backlog.addr {
                                    let diag = alloc::format!(
                                        "TCP_ACCEPT_FAIL: path={} raw_fd={} err={:?}\n",
                                        path, raw_fd, e,
                                    );
                                    if let Ok(f) = fs.open("/tmp/unix-port-trace.log", OFlags::CREAT | OFlags::RDWR | OFlags::APPEND, Mode::RWXU) {
                                        let _ = fs.write(&f, diag.as_bytes(), None);
                                        let _ = fs.close(&f);
                                    }
                                }
                                return None;
                            }
                        };
                        let proxy = listen.global.initialize_socket(
                            &accepted_fd,
                            SockType::Stream,
                            SockFlags::empty(),
                        );
                        Some(UnixConnectedStream {
                            addr: AddrView {
                                addr: Some(listen.backlog.addr.clone()),
                                peer: None,
                            },
                            transport: UnixTransport::Tcp { proxy },
                            peer_cred: listen.backlog.listener_cred,
                            pollee: Arc::new(Pollee::new()),
                        })
                    });

                    if let Some(connected) = result {
                        // Decrement the pending TCP connection counter.
                        self.with_state_ref(|state| {
                            if let Some(listen) = state.listen() {
                                listen.backlog.pending_tcp_connections
                                    .fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
                            }
                        });
                        if let Some(peer) = peer.as_deref_mut() {
                            *peer = connected.get_peer_addr();
                        }
                        return Ok(UnixSocketInner::Stream(UnixStream::new(
                            UnixStreamState::Connected(connected),
                        )));
                    }
                }

                Err(TryOpError::TryAgain)
            },
        )
        .map_err(Errno::from)
    }

    #[expect(clippy::too_many_arguments)]
    fn sendto(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        timeout: Option<Duration>,
        buf: &[u8],
        is_nonblocking: bool,
        addr: Option<UnixSocketAddr>,
        preserve_empty_record: bool,
        passed_fds: Vec<PassedFd>,
    ) -> Result<usize, Errno> {
        let mut msg = Some(Message {
            data: buf.to_vec(),
            passed_fds,
        });
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
                        if buf.is_empty() && !preserve_empty_record {
                            return Ok(0);
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

    #[expect(clippy::too_many_arguments)]
    fn recvfrom(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        timeout: Option<Duration>,
        buf: &mut [u8],
        is_nonblocking: bool,
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
        seqpacket: bool,
        received_fds: &mut Vec<PassedFd>,
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
                        let n = conn.try_recvfrom(buf, seqpacket, received_fds)?;
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
            UnixStreamState::Init(init) => init
                .addr
                .as_ref()
                .map_or(UnixSocketAddr::Unnamed, UnixSocketAddr::from),
            UnixStreamState::Listen(listen) => UnixSocketAddr::from(listen.get_local_addr()),
            UnixStreamState::Connected(connect) => connect.get_local_addr(),
        })
    }
    fn get_peer_addr(&self) -> Option<UnixSocketAddr> {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(_) | UnixStreamState::Listen(_) => None,
            UnixStreamState::Connected(connect) => Some(connect.get_peer_addr()),
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
struct DatagramMessage {
    data: Vec<u8>,
    /// File descriptors passed via `SCM_RIGHTS` ancillary data.
    passed_fds: Vec<PassedFd>,
    source: UnixSocketAddr,
}

#[derive(Clone)]
struct UnixDatagramEndpoint {
    send_channel: WriteEnd<DatagramMessage>,
}

#[derive(Clone)]
struct UnixDatagramPeer {
    send_channel: WriteEnd<DatagramMessage>,
    addr: UnixSocketAddr,
    peer_cred: Option<Ucred>,
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
        received_fds: &mut Vec<PassedFd>,
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
                // Extract any passed fds from the first message.
                if !msg.passed_fds.is_empty() {
                    received_fds.append(&mut msg.passed_fds);
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
            if n == 0 {
                break;
            }
            buf = &mut buf[n..];
        }
        if let (Some(src), Some(source_addr)) = (src, source_addr) {
            *source_addr = Some(src);
        }
        Ok(total_read)
    }
}

struct UnixDatagramInner<FS: ShimFS> {
    /// The local address this socket is bound to, if any.
    addr: Option<(UnixBoundSocketAddr<FS>, Arc<GlobalState<FS>>)>,
    /// The read end of the local socket's channel for receiving messages.
    /// Set when the socket is bound via `bind` or `new_pair`.
    recv_channel: Option<ReadEnd<DatagramMessage>>,
    /// The write end of the connected peer socket for sending messages.
    /// Set when the socket is connected via `connect` or `new_pair`.
    connected_send_channel: Option<UnixDatagramPeer>,
    pollee: Arc<Pollee<crate::Platform>>,
}
/// Represents a Unix datagram socket.
struct UnixDatagram<FS: ShimFS> {
    inner: RwLock<crate::Platform, UnixDatagramInner<FS>>,
}

impl<FS: ShimFS> Drop for UnixDatagramInner<FS> {
    fn drop(&mut self) {
        if let Some((addr, global)) = self.addr.take() {
            let key = addr.to_key();
            let mut table = global.unix_addr_table.write();
            // Only remove the entry if it matches the current socket
            if let Some(UnixEntry(UnixEntryInner::Datagram(endpoint))) = table.get(&key)
                && let Some(recv_channel) = &self.recv_channel
                && endpoint.send_channel.is_pair(recv_channel)
            {
                table.remove(&key);
            }
        }
    }
}

impl<FS: ShimFS> UnixDatagramInner<FS> {
    /// Binds this socket to the given address.
    fn bind(&mut self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
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
        let _ = task.global.unix_addr_table.write().insert(
            key,
            UnixEntry(UnixEntryInner::Datagram(UnixDatagramEndpoint {
                send_channel,
            })),
        );
        self.addr = Some((bound_addr, task.global.clone()));
        self.recv_channel = Some(recv_channel);
        Ok(())
    }
}

impl<FS: ShimFS> UnixDatagram<FS> {
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

    fn new_pair(peer_cred: Ucred) -> (UnixDatagram<FS>, UnixDatagram<FS>) {
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
                    connected_send_channel: Some(UnixDatagramPeer {
                        send_channel: send_channel_peer,
                        addr: UnixSocketAddr::Unnamed,
                        peer_cred: Some(peer_cred),
                    }),
                    pollee: pollee1,
                }),
            },
            UnixDatagram {
                inner: RwLock::new(UnixDatagramInner {
                    addr: None,
                    recv_channel: Some(recv_channel_peer),
                    connected_send_channel: Some(UnixDatagramPeer {
                        send_channel,
                        addr: UnixSocketAddr::Unnamed,
                        peer_cred: Some(peer_cred),
                    }),
                    pollee: pollee2,
                }),
            },
        )
    }

    /// Binds this socket to the given address.
    fn bind(&self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.inner.write().bind(task, addr)
    }

    /// Looks up a socket address and returns its write endpoint.
    fn lookup(&self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<UnixDatagramEndpoint, Errno> {
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
            UnixEntryInner::Datagram(endpoint) => Ok(endpoint.clone()),
        }
    }

    /// Connects this socket to a default peer address.
    ///
    /// Subsequent sends without an address will use this peer.
    fn connect(&self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        let endpoint = self.lookup(task, addr.clone())?;
        self.inner.write().connected_send_channel = Some(UnixDatagramPeer {
            send_channel: endpoint.send_channel,
            addr,
            peer_cred: None,
        });
        Ok(())
    }

    fn recvfrom(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        timeout: Option<Duration>,
        buf: &mut [u8],
        is_nonblocking: bool,
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
        received_fds: &mut Vec<PassedFd>,
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
                    recv_channel.try_read(buf, source_addr.as_deref_mut(), received_fds)
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
        task: &Task<FS>,
        timeout: Option<Duration>,
        buf: &[u8],
        is_nonblocking: bool,
        addr: Option<UnixSocketAddr>,
        passed_fds: Vec<PassedFd>,
    ) -> Result<usize, Errno> {
        let source = self.get_local_addr();
        let send_channel = if let Some(addr) = addr {
            self.lookup(task, addr)?.send_channel
        } else if let Some(connected_send_channel) = &self.inner.read().connected_send_channel {
            connected_send_channel.send_channel.clone()
        } else {
            return Err(Errno::ENOTCONN);
        };
        send_channel.write(
            &task.wait_cx(),
            timeout,
            DatagramMessage {
                data: buf.to_vec(),
                passed_fds,
                source,
            },
            is_nonblocking,
        )?;
        Ok(buf.len())
    }

    fn get_local_addr(&self) -> UnixSocketAddr {
        self.inner
            .read()
            .addr
            .as_ref()
            .map_or(UnixSocketAddr::Unnamed, |(addr, _)| {
                UnixSocketAddr::from(addr)
            })
    }
    fn get_peer_addr(&self) -> Option<UnixSocketAddr> {
        self.inner
            .read()
            .connected_send_channel
            .as_ref()
            .map(|peer| peer.addr.clone())
    }

    fn peer_cred(&self) -> Option<Ucred> {
        self.inner
            .read()
            .connected_send_channel
            .as_ref()
            .and_then(|peer| peer.peer_cred)
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::empty();
        if let Some(recv_channel) = &self.inner.read().recv_channel {
            if recv_channel.is_shutdown() || recv_channel.is_peer_shutdown() {
                events |= Events::IN | Events::RDHUP;
            } else if !recv_channel.is_empty() {
                events |= Events::IN;
            }
        }
        if let Some(connected_send_channel) = &self.inner.read().connected_send_channel {
            if connected_send_channel.send_channel.is_peer_shutdown() {
                events |= Events::HUP;
            } else if !connected_send_channel.send_channel.is_full() {
                events |= Events::OUT;
            }
        } else {
            // If not connected, allow to sendto any address?
            events |= Events::OUT;
        }
        events
    }
}

enum UnixSocketInner<FS: ShimFS> {
    Stream(UnixStream<FS>),
    Datagram(UnixDatagram<FS>),
}
pub(crate) struct UnixSocket<FS: ShimFS> {
    inner: UnixSocketInner<FS>,
    /// The socket type as requested by the caller (e.g. SOCK_SEQPACKET),
    /// which may differ from the transport used by `inner`.
    sock_type: SockType,
    status: AtomicU32,
    options: Mutex<crate::Platform, SocketOptions>,
}

impl<FS: ShimFS> UnixSocket<FS> {
    fn new_with_inner(inner: UnixSocketInner<FS>, sock_type: SockType, flags: SockFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
        Self {
            inner,
            sock_type,
            status: AtomicU32::new(status.bits()),
            options: litebox::sync::Mutex::new(SocketOptions::default()),
        }
    }

    pub(super) fn new(sock_type: SockType, flags: SockFlags) -> Option<Self> {
        let inner = match sock_type {
            // SeqPacket uses stream transport. This does not preserve message
            // boundaries (reads can coalesce/split), but suffices for current
            // callers (Rust Command::spawn error pipe sends a single message).
            SockType::Stream | SockType::SeqPacket => UnixSocketInner::Stream(UnixStream::new(
                UnixStreamState::Init(UnixInitStream::new()),
            )),
            SockType::Datagram => UnixSocketInner::Datagram(UnixDatagram::new()),
            e => {
                log_unsupported!("Unsupported unix socket type: {:?}", e);
                return None;
            }
        };
        Some(Self::new_with_inner(inner, sock_type, flags))
    }

    pub(super) fn bind(&self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.bind(task, addr),
            UnixSocketInner::Datagram(datagram) => datagram.bind(task, addr),
        }
    }

    pub(super) fn sock_type(&self) -> SockType {
        self.sock_type
    }

    /// Returns `true` if this is a connected stream socket.
    pub(super) fn is_connected(&self) -> bool {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.with_state_ref(|s| s.connected().is_some()),
            UnixSocketInner::Datagram(_) => false,
        }
    }

    /// Returns a pair identifier for connected stream sockets, or `None`
    /// for init/listen/datagram sockets.
    pub(crate) fn socket_pair_id(&self) -> Option<usize> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.with_state_ref(|s| s.connected().map(UnixConnectedStream::socket_pair_id))
            }
            UnixSocketInner::Datagram(_) => None,
        }
    }

    /// Pop one message from the recv channel (connected stream only).
    /// Returns `None` if empty, not connected, or datagram.
    pub(crate) fn drain_recv_one(&self) -> Option<Message> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.with_state_ref(|s| {
                s.connected().and_then(|c| match &c.transport {
                    UnixTransport::Channel { recv, .. } => recv
                        .peek_and_consume_one(|msg| {
                            Ok((
                                true,
                                Message {
                                    data: core::mem::take(&mut msg.data),
                                    passed_fds: core::mem::take(&mut msg.passed_fds),
                                },
                            ))
                        })
                        .ok(),
                    UnixTransport::Tcp { proxy } => {
                        use litebox::net::socket_channel::NetworkProxy;
                        if let NetworkProxy::Stream(stream) = proxy.as_ref() {
                            let mut buf = alloc::vec![0u8; UNIX_BUF_SIZE];
                            match stream.try_read(
                                &mut buf,
                                litebox::net::ReceiveFlags::empty(),
                                None,
                            ) {
                                Ok(n) => {
                                    buf.truncate(n);
                                    Some(Message {
                                        data: buf,
                                        passed_fds: Vec::new(),
                                    })
                                }
                                Err(_) => None,
                            }
                        } else {
                            None
                        }
                    }
                })
            }),
            UnixSocketInner::Datagram(_) => None,
        }
    }

    pub(super) fn has_timeouts(&self) -> bool {
        let opts = self.options.lock();
        opts.recv_timeout.is_some() || opts.send_timeout.is_some()
    }

    pub(super) fn listen(
        &self,
        task: &Task<FS>,
        backlog: u16,
        global: &Arc<GlobalState<FS>>,
    ) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.listen(task, backlog, global),
            UnixSocketInner::Datagram(_) => Err(Errno::EOPNOTSUPP),
        }
    }

    pub(super) fn connect(&self, task: &Task<FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.connect(task, addr, self.get_status().contains(OFlags::NONBLOCK))
            }
            UnixSocketInner::Datagram(datagram) => datagram.connect(task, addr),
        }
    }

    pub(super) fn accept(
        &self,
        task: Option<&Task<FS>>,
        cx: &WaitContext<'_, crate::Platform>,
        flags: SockFlags,
        peer: Option<&mut UnixSocketAddr>,
    ) -> Result<UnixSocket<FS>, Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                let accepted = stream.accept(
                    task,
                    cx,
                    peer,
                    self.get_status().contains(OFlags::NONBLOCK)
                        | flags.contains(SockFlags::NONBLOCK),
                )?;
                Ok(UnixSocket::new_with_inner(accepted, self.sock_type, flags))
            }
            UnixSocketInner::Datagram(_) => Err(Errno::EOPNOTSUPP),
        }
    }

    pub(super) fn sendto(
        &self,
        task: &Task<FS>,
        buf: &[u8],
        flags: SendFlags,
        addr: Option<UnixSocketAddr>,
        passed_fds: Vec<PassedFd>,
    ) -> Result<usize, Errno> {
        let supported_flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported sendto flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let is_nonblocking =
            flags.contains(SendFlags::DONTWAIT) || self.get_status().contains(OFlags::NONBLOCK);
        let timeout = self.options.lock().send_timeout;
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.sendto(
                &task.wait_cx(),
                timeout,
                buf,
                is_nonblocking,
                addr,
                self.sock_type == SockType::SeqPacket,
                passed_fds,
            ),
            UnixSocketInner::Datagram(datagram) => {
                datagram.sendto(task, timeout, buf, is_nonblocking, addr, passed_fds)
            }
        }
    }

    /// Blocking write for worker-exec stdio bridging (no Task needed).
    pub(crate) fn send_bytes(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        buf: &[u8],
    ) -> Result<usize, Errno> {
        let is_nonblocking = self.get_status().contains(OFlags::NONBLOCK);
        let timeout = self.options.lock().send_timeout;
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.sendto(cx, timeout, buf, is_nonblocking, None, false, Vec::new())
            }
            UnixSocketInner::Datagram(_) => Err(Errno::ENOTSUP),
        }
    }

    pub(super) fn recvfrom(
        &self,
        cx: &WaitContext<'_, crate::Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<UnixSocketAddr>>,
        received_fds: &mut Vec<PassedFd>,
    ) -> Result<usize, Errno> {
        let supported_flags =
            ReceiveFlags::DONTWAIT | ReceiveFlags::NOSIGNAL | ReceiveFlags::CMSG_CLOEXEC;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvfrom flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let is_nonblocking =
            flags.contains(ReceiveFlags::DONTWAIT) || self.get_status().contains(OFlags::NONBLOCK);
        let timeout = self.options.lock().recv_timeout;
        let seqpacket = self.sock_type == SockType::SeqPacket;
        let ret = match &self.inner {
            UnixSocketInner::Stream(stream) => stream.recvfrom(
                cx,
                timeout,
                buf,
                is_nonblocking,
                source_addr,
                seqpacket,
                received_fds,
            ),
            UnixSocketInner::Datagram(datagram) => {
                datagram.recvfrom(cx, timeout, buf, is_nonblocking, source_addr, received_fds)
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

    /// Shutdown the read side, write side, or both of a Unix socket.
    pub(super) fn shutdown(&self, read: bool, write: bool) {
        if let UnixSocketInner::Stream(stream) = &self.inner {
            let state = stream.state.read();
            if let Some(UnixStreamState::Connected(conn)) = &*state {
                match &conn.transport {
                    UnixTransport::Channel { recv, send } => {
                        if read {
                            recv.shutdown();
                        }
                        if write {
                            send.shutdown();
                        }
                    }
                    UnixTransport::Tcp { proxy } => {
                        use litebox::net::socket_channel::NetworkProxy;
                        if let NetworkProxy::Stream(stream) = proxy.as_ref() {
                            if read {
                                stream.shutdown_read();
                            }
                            if write {
                                stream.shutdown_write();
                            }
                        }
                    }
                }
            }
        }
    }
    pub(super) fn get_peer_addr(&self) -> Option<UnixSocketAddr> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.get_peer_addr(),
            UnixSocketInner::Datagram(datagram) => datagram.get_peer_addr(),
        }
    }

    pub(super) fn new_connected_pair(
        ty: SockType,
        flags: SockFlags,
        peer_cred: Ucred,
    ) -> Option<(UnixSocket<FS>, UnixSocket<FS>)> {
        match ty {
            SockType::Stream | SockType::SeqPacket => {
                let (conn1, conn2) =
                    UnixConnectedStream::new_pair(None, None, None, peer_cred, peer_cred);
                Some((
                    UnixSocket::new_with_inner(
                        UnixSocketInner::Stream(UnixStream::new(UnixStreamState::Connected(conn1))),
                        ty,
                        flags,
                    ),
                    UnixSocket::new_with_inner(
                        UnixSocketInner::Stream(UnixStream::new(UnixStreamState::Connected(conn2))),
                        ty,
                        flags,
                    ),
                ))
            }
            SockType::Datagram => {
                let (datagram1, datagram2) = UnixDatagram::new_pair(peer_cred);
                Some((
                    UnixSocket::new_with_inner(UnixSocketInner::Datagram(datagram1), ty, flags),
                    UnixSocket::new_with_inner(UnixSocketInner::Datagram(datagram2), ty, flags),
                ))
            }
            _ => None,
        }
    }

    pub(super) fn setsockopt(
        &self,
        global: &GlobalState<FS>,
        optname: SocketOptionName,
        optval: ConstPtr<u8>,
        optlen: usize,
    ) -> Result<(), Errno> {
        match global.setsockopt_common(optname, optval, optlen, |so, value| {
            match (so, value) {
                (SocketOption::RCVTIMEO, SocketOptionValue::Timeout(timeout)) => {
                    self.options.lock().recv_timeout = timeout;
                }
                (SocketOption::SNDTIMEO, SocketOptionValue::Timeout(timeout)) => {
                    self.options.lock().send_timeout = timeout;
                }
                (SocketOption::LINGER, SocketOptionValue::Timeout(timeout)) => {
                    self.options.lock().linger_timeout = timeout;
                }
                (SocketOption::REUSEADDR, SocketOptionValue::U32(val)) => {
                    self.options.lock().reuse_address = val != 0;
                }
                (SocketOption::KEEPALIVE, SocketOptionValue::U32(val)) => {
                    self.options.lock().keep_alive = val != 0;
                }
                (SocketOption::BROADCAST, SocketOptionValue::U32(val)) => {
                    self.options.lock().broadcast = val != 0;
                }
                _ => unreachable!(),
            }
            Ok(())
        }) {
            Err(Errno::ENOPROTOOPT) => {} // continue to handle unix
            other => return other,
        }

        match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS | IpOption::RECVERR | IpOption::MTU_DISCOVER | IpOption::PKTINFO => {
                    Err(Errno::EOPNOTSUPP)
                }
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
                // We use fixed buffer size for now
                SocketOption::RCVBUF | SocketOption::SNDBUF => Err(Errno::EOPNOTSUPP),
            },
            SocketOptionName::TCP(_) => Err(Errno::EOPNOTSUPP),
        }
    }
    pub(super) fn getsockopt(
        &self,
        global: &GlobalState<FS>,
        optname: SocketOptionName,
        optval: MutPtr<u8>,
        len: u32,
    ) -> Result<usize, Errno> {
        match global.getsockopt_common(optname, optval, len, |sopt| match sopt {
            SocketOption::RCVTIMEO => SocketOptionValue::Timeout(self.options.lock().recv_timeout),
            SocketOption::SNDTIMEO => SocketOptionValue::Timeout(self.options.lock().send_timeout),
            SocketOption::LINGER => SocketOptionValue::Timeout(self.options.lock().linger_timeout),
            SocketOption::REUSEADDR => {
                SocketOptionValue::U32(u32::from(self.options.lock().reuse_address))
            }
            SocketOption::KEEPALIVE => {
                SocketOptionValue::U32(u32::from(self.options.lock().keep_alive))
            }
            SocketOption::BROADCAST => {
                SocketOptionValue::U32(u32::from(self.options.lock().broadcast))
            }
            _ => unreachable!(),
        }) {
            Err(Errno::ENOPROTOOPT) => {} // continue to handle unix
            other => return other,
        }

        let val: u32 = match optname {
            SocketOptionName::IP(ip) => match ip {
                IpOption::TOS | IpOption::RECVERR | IpOption::MTU_DISCOVER | IpOption::PKTINFO => {
                    return Err(Errno::EOPNOTSUPP);
                }
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
                SocketOption::TYPE => self.sock_type as u32,
                SocketOption::RCVBUF | SocketOption::SNDBUF => UNIX_BUF_SIZE.truncate(),
                SocketOption::PEERCRED => {
                    let ucred = match &self.inner {
                        UnixSocketInner::Stream(stream) => stream.with_state_ref(|state| {
                            state
                                .connected()
                                .map_or(UNCONNECTED_PEER_CRED, UnixConnectedStream::peer_cred)
                        }),
                        UnixSocketInner::Datagram(datagram) => {
                            datagram.peer_cred().unwrap_or(UNCONNECTED_PEER_CRED)
                        }
                    };
                    return super::write_to_user(ucred, optval, len);
                }
            },
            SocketOptionName::TCP(_) => return Err(Errno::EOPNOTSUPP),
        };
        super::write_to_user(val, optval, len)
    }

    super::common_functions_for_file_status!();
}

impl<FS: ShimFS> IOPollable for UnixSocket<FS> {
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

pub(crate) struct UnixEntry<FS: ShimFS>(UnixEntryInner<FS>);
enum UnixEntryInner<FS: ShimFS> {
    Stream(Arc<Backlog<FS>>),
    Datagram(UnixDatagramEndpoint),
}

/// Type alias for the global Unix socket address table.
pub(crate) type UnixAddrTable<FS> = BTreeMap<UnixSocketAddrKey, UnixEntry<FS>>;

/// Bridge observer that accepts cross-worker TCP connections when the
/// network thread signals that a TCP handshake has completed. Pushes
/// accepted connections into the unix socket backlog so that the guest's
/// unix accept() returns them.
///
/// IMPORTANT: on_events is called from the network thread which holds
/// the net mutex. We must NOT call Network::accept() here (deadlock).
/// Instead we just notify the backlog pollee to wake the guest's
/// accept() which will do the Network::accept() on the guest thread.
struct BacklogTcpBridge<FS: ShimFS> {
    backlog: Arc<Backlog<FS>>,
}

// Safety: BacklogTcpBridge holds an Arc, thread-safe.
unsafe impl<FS: ShimFS> Send for BacklogTcpBridge<FS> {}
unsafe impl<FS: ShimFS> Sync for BacklogTcpBridge<FS> {}

impl<FS: ShimFS> litebox::event::observer::Observer<Events> for BacklogTcpBridge<FS> {
    fn on_events(&self, events: &Events) {
        if events.contains(Events::IN) {
            // Signal that a cross-worker TCP connection is ready.
            // This makes check_io_events() return IN so epoll wakes tokio.
            self.backlog
                .pending_tcp_connections
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            BRIDGE_FIRE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            self.backlog.pollee.notify_observers(Events::IN);
        }
    }
}

/// Global counter for bridge firings (diagnostic).
static BRIDGE_FIRE_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Returns the number of times any bridge observer has fired.
pub(crate) fn bridge_fire_count() -> u32 {
    BRIDGE_FIRE_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

// ── Cross-worker unix socket discovery via sidecar metadata files ──
//
// When a unix socket listener is created, a sidecar file is written at
// `<path>.litebox-uds-meta` containing the TCP port number that backs
// this listener for cross-worker connections. Other workers read this
// file when their local unix_addr_table doesn't have the entry.

/// Sidecar file suffix for cross-worker unix socket discovery.
const SIDECAR_SUFFIX: &str = ".litebox-uds-meta";

/// Build the sidecar metadata path for a unix socket path.
fn sidecar_path(sock_path: &str) -> String {
    alloc::format!("{}{}", sock_path, SIDECAR_SUFFIX)
}

/// Write the TCP port to a sidecar metadata file.
fn write_sidecar<FS: ShimFS>(fs: &FS, sock_path: &str, tcp_port: u16) {
    let path = sidecar_path(sock_path);
    let data = alloc::format!("{}", tcp_port);
    if let Ok(fd) = fs.open(
        path.as_str(),
        OFlags::CREAT | OFlags::RDWR | OFlags::TRUNC,
        Mode::RWXU,
    ) {
        let _ = fs.write(&fd, data.as_bytes(), Some(0));
        let _ = fs.close(&fd);
    }
}

/// Read the TCP port from a sidecar metadata file. Returns None if not found.
fn read_sidecar<FS: ShimFS>(fs: &FS, sock_path: &str) -> Option<u16> {
    let path = sidecar_path(sock_path);
    let fd = fs.open(path.as_str(), OFlags::RDONLY, Mode::empty()).ok()?;
    let mut buf = [0u8; 16];
    let n = fs.read(&fd, &mut buf, Some(0)).ok()?;
    let _ = fs.close(&fd);
    let s = core::str::from_utf8(&buf[..n]).ok()?;
    s.trim().parse::<u16>().ok()
}

/// Remove the sidecar metadata file.
fn remove_sidecar<FS: ShimFS>(fs: &FS, sock_path: &str) {
    let path = sidecar_path(sock_path);
    let _ = fs.unlink(path.as_str());
}
