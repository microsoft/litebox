// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hybrid vsock: the broker's vsock sockets bridged to host Unix stream
//! sockets, with the convention of Firecracker's and Cloud Hypervisor's
//! hybrid vsock, which Kata's runtime speaks (`hvsock://PATH:PORT`).
//!
//! [`HybridVsock`] runs [`VsockDeviceProvider`], which implements the
//! sockets, on a bridge that implements its [`Vsock`] device with host Unix
//! sockets, and a thread that polls them.
//!
//! - **Paths.** At start, the bridge resolves `PATH`'s directory, once, to an
//!   absolute canonical path, which must exist: `PATH` and every `PATH_P`
//!   are in it, whatever the working directory later is.
//! - **Host to guest.** The bridge listens on `PATH`, a Unix stream socket it
//!   creates (it fails if `PATH` exists). A host client connects and writes
//!   `CONNECT <port>\n` (a decimal `u32`, at most [`MAX_HANDSHAKE`] bytes
//!   with the newline): a request for a connection to the guest's port, from
//!   a host port the bridge assigns, counting up from 2^30 and skipping
//!   ports in use. If the guest's listener on that port takes it (its
//!   backlog has room), the bridge writes `OK <host port>\n`, and the stream
//!   is the connection, starting with whatever the client wrote after the
//!   newline. If no listener takes it, or the line is malformed, too long,
//!   or not complete within [`HANDSHAKE_TIMEOUT`], the bridge closes the
//!   stream.
//! - **Guest to host.** A guest's connect to the host's port `P` connects to
//!   `PATH_P` (`PATH`, `_`, decimal `P`). A connected stream is the
//!   connection, at once; if the connect fails (`PATH_P` is missing, or does
//!   not listen, or its backlog is full), the guest's fails with
//!   `ECONNRESET`, as when a VMM resets it.
//! - **Data** moves straight between the guest's socket and the host's
//!   stream, which buffers it: the host's data until the guest reads it,
//!   and the guest's until the host reads it, within the stream's own
//!   buffers. Shutdowns are the stream's, so a guest's `SHUT_RD` makes the
//!   host's sends fail. A guest's close shuts the stream down both ways,
//!   drops what the host sent that the guest did not read (so the host reads
//!   to EOF rather than a reset), and closes it: the guest's data is already
//!   the host's, so nothing lingers.
//!
//! One thread waits, with `epoll`, for the listener, the waiting clients,
//! the connections, and an eventfd that operations write when the provider
//! needs a poll it would not otherwise get (a connect started, a close, a
//! backlog of requests, a connection a read left ended); and calls the
//! provider's poll after any event, or at the provider's next deadline.
//!
//! **Lifetime.** [`HybridVsock`] owns the bridge, and
//! [`HybridVsock::provider`] is what the broker installs. Sockets keep the
//! provider's and the bridge's state alive, but only dropping the owner
//! stops the bridge, for good: guest connects then fail, as refused, and
//! the host's requests are refused; every stream and the listener are
//! closed; the thread ends; a last poll publishes each socket's end; and
//! `PATH` is removed if it is still the socket the bridge bound. The last
//! poll, and so the drop, waits for guest operations in flight, which hold
//! the provider's lock against it, until the provider has settled. Guest
//! listeners stay listening and never get another connection, as a Linux
//! vsock listener whose host never connects: creating sockets and listening
//! still work, and connects fail. If the thread fails, it logs why and
//! stops the bridge the same way, but `PATH` stays until the owner is
//! dropped.
//!
//! **Trust.** Host clients are untrusted. Their handshakes are bounded in
//! length, number ([`MAX_PENDING`]) and time, and the provider bounds what
//! each poll does for the host. The host's connections, from accepting the
//! client until the provider forgets the connection (including those that
//! wait in a guest listener's backlog), number at most
//! [`MAX_HOST_CONNECTIONS`]; beyond either bound, new clients are closed at
//! once. The guest's own connections are bounded by the broker's socket
//! quota, as each is a guest socket's. An accept that fails other than
//! transiently (e.g., out of descriptors) leaves the client queued, so the
//! bridge stops watching `PATH` for a while rather than spin.
//!
//! Anyone who can connect to `PATH` reaches the guest's listeners, and anyone
//! who can create `PATH_P` receives the guest's connects to port `P`.
//! Connecting to a Unix socket needs write permission on it, so the umask
//! (which sets `PATH`'s mode) and `PATH`'s directory are the access control:
//! the directory must be writable only by the broker's user, as anyone who
//! can write it can take a `PATH_P` or replace `PATH`. Removing `PATH` checks
//! its identity, then unlinks it, in two steps. Removing `PATH` and
//! connecting to `PATH_P` are safe only if no other process, including ones
//! running as the broker's user, creates, replaces or renames entries in
//! `PATH`'s directory (or its ancestors) while the bridge runs; otherwise the
//! bridge may remove an entry it did not create, or connect the guest to a
//! listener it did not expect. `PATH_P`'s suffix is a decimal `u32`, so a
//! guest cannot name a path outside that directory.
//!
//! **Locks.** The provider's lock, then the bridge's (each [`Vsock`] call);
//! the thread takes the bridge's alone, and never the provider's while it
//! holds it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use litebox_broker_core::vsock::VsockProvider;
use litebox_broker_core::vsock::device::{
    ConnectState, ConnectionId, ConnectionStatus, Vsock, VsockDeviceProvider,
};
use litebox_broker_protocol::vsock::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_PORT_ANY};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, epoll, eventfd, poll};
use rustix::io::{Errno, ioctl_fionread, read, write};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, Shutdown, SocketAddrUnix, SocketFlags, SocketType,
    accept_with, bind, connect, listen, recv, send, shutdown, socket_with, sockopt,
};

use crate::time::{LinuxInstant, LinuxTimeProvider};

/// The longest handshake line, with its newline.
pub const MAX_HANDSHAKE: usize = 32;

/// How long a host client has to write its handshake line.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Host clients waiting for an answer at once: writing their handshake, or
/// waiting for the guest's listener to take their request.
pub const MAX_PENDING: usize = 32;

/// Host clients' connections at once, from accepting the client until the
/// provider forgets the connection: writing their handshake, requested, or
/// connected, including those waiting in a guest listener's backlog.
pub const MAX_HOST_CONNECTIONS: usize = 128;

/// The guest's CID unless configured otherwise: the first that is not
/// reserved.
pub const DEFAULT_GUEST_CID: u32 = 3;

/// Whether `cid` can be a guest's: not one of the reserved CIDs 0 to 2 (the
/// host's), nor `VMADDR_CID_ANY`.
#[must_use]
pub fn is_guest_cid(cid: u32) -> bool {
    cid > VMADDR_CID_HOST && cid != VMADDR_CID_ANY
}

/// The first host port the bridge assigns to a host client's connection.
const FIRST_HOST_PORT: u32 = 1 << 30;

/// Host clients accepted per wakeup; the rest wait for the next.
const MAX_ACCEPTS: usize = 64;

/// How long the bridge stops watching `PATH` after an accept failed other
/// than transiently.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// What the listener on `PATH` queues before the bridge accepts.
const LISTEN_BACKLOG: i32 = 128;

/// Bytes of a closed connection's unread data dropped, so the host reads to
/// EOF rather than a reset; with more, the host gets a reset.
const MAX_CLOSE_DRAIN: usize = 1 << 20;

/// The length of a Unix socket path, without its NUL.
const MAX_SOCKET_PATH: usize = 108;

/// The longest `PATH_P` suffix: `_4294967295`.
const MAX_PORT_SUFFIX: usize = 11;

const WAKE_TOKEN: u64 = 0;
const LISTENER_TOKEN: u64 = 1;
const FIRST_STREAM_TOKEN: u64 = 2;
const MAX_EVENTS: usize = 64;

/// What the thread waits for on each stream; edge-triggered, as every event
/// leads to a poll, which reads each connection's state afresh.
const STREAM_EVENTS: epoll::EventFlags = epoll::EventFlags::IN
    .union(epoll::EventFlags::OUT)
    .union(epoll::EventFlags::RDHUP)
    .union(epoll::EventFlags::ET);

/// The broker's vsock sockets, bridged to host Unix sockets at a path (see
/// the [module](self) docs): the bridge's owner. Dropping it stops the
/// bridge, once guest operations in flight end.
pub struct HybridVsock {
    provider: Arc<VsockDeviceProvider<LinuxInstant>>,
    bridge: Arc<Bridge>,
    thread: Option<JoinHandle<()>>,
    /// Dropped after the thread ends.
    path: BoundPath,
}

impl HybridVsock {
    /// Starts bridging a guest with CID `guest_cid` at `path`, which must
    /// not exist, in a directory that must exist and be writable only by
    /// the broker's user (see the [module](self) docs); `seed` (e.g., from a
    /// CSPRNG) starts the ephemeral ports.
    ///
    /// Fails with `InvalidInput` for a CID that is not a guest's
    /// ([`is_guest_cid`]), or a path with no file name or too long for the
    /// `PATH_P` paths; with `AddrInUse` if `path` exists; or with the error
    /// resolving its directory, creating the listener, or the thread. The
    /// error names the path.
    pub fn start(path: &Path, guest_cid: u32, seed: u64) -> IoResult<Self> {
        Self::start_with(path, guest_cid, seed, HANDSHAKE_TIMEOUT)
    }

    fn start_with(
        path: &Path,
        guest_cid: u32,
        seed: u64,
        handshake_timeout: Duration,
    ) -> IoResult<Self> {
        if !is_guest_cid(guest_cid) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("vsock CID {guest_cid} is not a guest's"),
            ));
        }
        let path = resolve(path).map_err(|error| named(error, path))?;
        let (bridge, bound) = Bridge::bind(&path, guest_cid, handshake_timeout)
            .map_err(|error| named(error, &path))?;
        let bridge = Arc::new(bridge);
        let provider = Arc::new(VsockDeviceProvider::new(
            bridge.clone(),
            Box::new(|| LinuxTimeProvider.now()),
            seed,
        ));
        let thread = thread::Builder::new()
            .name("litebox-broker-vsock-uds".into())
            .spawn({
                let (bridge, provider) = (bridge.clone(), provider.clone());
                move || run(&bridge, &provider)
            })
            .map_err(|error| named(error, &path))?;
        Ok(Self {
            provider,
            bridge,
            thread: Some(thread),
            path: bound,
        })
    }

    /// The provider to back the broker's vsock sockets with; its sockets
    /// work until this is dropped.
    #[must_use]
    pub fn provider(&self) -> Arc<dyn VsockProvider> {
        self.provider.clone()
    }
}

impl fmt::Debug for HybridVsock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HybridVsock")
            .field("path", &self.path.path)
            .field("guest_cid", &self.bridge.guest_cid)
            .finish_non_exhaustive()
    }
}

impl Drop for HybridVsock {
    fn drop(&mut self) {
        self.bridge.stop();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            std::eprintln!("hybrid vsock bridge thread panicked");
        }
        final_poll(&self.provider);
    }
}

/// `PATH`, as the bridge bound it: removed when dropped, if still that
/// socket. The check and the unlink are two steps, so this is safe only if
/// no other process, including ones running as the broker's user, creates,
/// replaces or renames entries in `PATH`'s directory (or its ancestors)
/// while the bridge runs; otherwise it may remove an entry the bridge did
/// not create.
struct BoundPath {
    path: PathBuf,
    /// Its device and inode, right after the bind.
    identity: (u64, u64),
}

impl BoundPath {
    /// The socket just bound at `path`.
    fn identify(path: &Path) -> IoResult<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "replaced right after the bind",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}

impl Drop for BoundPath {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == self.identity
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// `path` in its directory's absolute canonical path.
fn resolve(path: &Path) -> IoResult<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "names no file"))?;
    let directory = match path.parent() {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        _ => Path::new("."),
    };
    let path = directory.canonicalize()?.join(name);
    if path.as_os_str().len() + MAX_PORT_SUFFIX > MAX_SOCKET_PATH {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "too long for its port paths",
        ));
    }
    Ok(path)
}

/// `error`, naming `path`, of the same kind.
fn named(error: Error, path: &Path) -> Error {
    Error::new(
        error.kind(),
        format!("hybrid vsock {}: {error}", path.display()),
    )
}

/// `PATH_P`, for `PATH` and port `P`.
fn port_path(path: &Path, port: u32) -> PathBuf {
    let mut path = path.as_os_str().to_owned();
    path.push(format!("_{port}"));
    path.into()
}

/// The provider's [`Vsock`] device: the host's Unix streams, by connection.
struct Bridge {
    /// `PATH`, absolute, in its directory's canonical path.
    path: PathBuf,
    guest_cid: u32,
    handshake_timeout: Duration,
    epoll: OwnedFd,
    /// An eventfd that wakes the thread.
    wake: OwnedFd,
    state: Mutex<State>,
    /// The thread's wakeups.
    #[cfg(test)]
    wakeups: std::sync::atomic::AtomicU64,
}

struct State {
    /// Set once, by [`Bridge::stop`]: no stream is made after.
    stopped: bool,
    /// `None` once stopped.
    listener: Option<OwnedFd>,
    /// While the thread does not watch the listener, after an accept failed:
    /// when it watches it again.
    accept_retry: Option<LinuxInstant>,
    next_token: u64,
    /// Host clients writing their handshake, by epoll token.
    handshakes: HashMap<u64, Handshake>,
    /// The host's requests, oldest first, for the provider to take.
    requests: VecDeque<ConnectionId>,
    connections: BTreeMap<ConnectionId, Connection>,
    next_host_port: u32,
    /// A read left a connection ended and read, which the provider forgets
    /// at a poll nothing else may cause.
    reclaim: bool,
}

struct Handshake {
    stream: OwnedFd,
    deadline: LinuxInstant,
}

enum Connection {
    /// A host client's request, which waits for the provider's answer.
    Requested(OwnedFd),
    /// Connected, by a host client (`from_host`) or the guest.
    Live { stream: OwnedFd, from_host: bool },
    /// A guest's connect that failed.
    Failed,
    /// Closed by the guest.
    Closed { from_host: bool },
}

impl Connection {
    fn is_host_initiated(&self) -> bool {
        match self {
            Self::Requested(_) => true,
            Self::Live { from_host, .. } | Self::Closed { from_host } => *from_host,
            Self::Failed => false,
        }
    }
}

impl Bridge {
    /// Creates the listener on `path`, and the thread's epoll and eventfd.
    fn bind(
        path: &Path,
        guest_cid: u32,
        handshake_timeout: Duration,
    ) -> IoResult<(Self, BoundPath)> {
        let address = SocketAddrUnix::new(path)?;
        let epoll = epoll::create(epoll::CreateFlags::CLOEXEC)?;
        let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        // Fails if `path` exists.
        bind(&listener, &address)?;
        // Removes `path` from here on, if setup fails.
        let bound = BoundPath::identify(path)?;
        listen(&listener, LISTEN_BACKLOG)?;
        epoll::add(
            &epoll,
            &wake,
            epoll::EventData::new_u64(WAKE_TOKEN),
            epoll::EventFlags::IN,
        )?;
        epoll::add(
            &epoll,
            &listener,
            epoll::EventData::new_u64(LISTENER_TOKEN),
            epoll::EventFlags::IN,
        )?;
        let mut state = State::new();
        state.listener = Some(listener);
        let bridge = Self {
            path: path.to_owned(),
            guest_cid,
            handshake_timeout,
            epoll,
            wake,
            state: Mutex::new(state),
            #[cfg(test)]
            wakeups: std::sync::atomic::AtomicU64::new(0),
        };
        Ok((bridge, bound))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("hybrid vsock bridge lock poisoned")
    }

    /// Wakes the thread, to poll the provider.
    fn wake(&self) {
        if let Err(error) = signal(&self.wake) {
            std::eprintln!("hybrid vsock bridge wakeup failed: {error}");
        }
    }

    /// Connects to the host's `PATH_P`, for port `P`; the connected stream,
    /// registered with the thread.
    fn connect_host(&self, state: &mut State, port: u32) -> IoResult<OwnedFd> {
        let address = SocketAddrUnix::new(port_path(&self.path, port))?;
        let stream = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )?;
        // A Unix stream connects at once, or fails (`EAGAIN` if the
        // listener's backlog is full).
        connect(&stream, &address)?;
        state.register(&self.epoll, &stream)?;
        Ok(stream)
    }

    /// Stops bridging, for good: closes every stream and the listener, and
    /// wakes the thread, which ends.
    fn stop(&self) {
        let mut state = self.lock();
        state.stopped = true;
        state.listener = None;
        state.accept_retry = None;
        state.handshakes.clear();
        state.requests.clear();
        state.connections.clear();
        drop(state);
        self.wake();
    }
}

impl State {
    fn new() -> Self {
        Self {
            stopped: false,
            listener: None,
            accept_retry: None,
            next_token: FIRST_STREAM_TOKEN,
            handshakes: HashMap::new(),
            requests: VecDeque::new(),
            connections: BTreeMap::new(),
            next_host_port: FIRST_HOST_PORT,
            reclaim: false,
        }
    }

    /// Registers `stream` with the thread's `epoll`, under a new token.
    fn register(&mut self, epoll: &OwnedFd, stream: &OwnedFd) -> IoResult<u64> {
        // Every stream the bridge reads comes here first. Urgent (`MSG_OOB`)
        // data is read inline, as `FIONREAD` counts it and `status` relies on.
        sockopt::set_socket_oobinline(stream, true)?;
        let token = self.next_token;
        self.next_token += 1;
        epoll::add(
            epoll,
            stream,
            epoll::EventData::new_u64(token),
            STREAM_EVENTS,
        )?;
        Ok(token)
    }

    /// The host clients' connections, from their accept until forgotten.
    fn host_connections(&self) -> usize {
        self.handshakes.len()
            + self
                .connections
                .values()
                .filter(|connection| connection.is_host_initiated())
                .count()
    }

    /// Accepts host clients, with `handshake_timeout` to write their line;
    /// beyond [`MAX_PENDING`] waiting, or [`MAX_HOST_CONNECTIONS`], closes
    /// them at once. After an accept fails other than transiently, stops
    /// watching the listener for [`ACCEPT_RETRY`].
    fn accept(
        &mut self,
        epoll: &OwnedFd,
        now: LinuxInstant,
        handshake_timeout: Duration,
    ) -> IoResult<()> {
        let deadline = now.checked_add(handshake_timeout).unwrap_or(now);
        let mut host_connections = self.host_connections();
        for _ in 0..MAX_ACCEPTS {
            let Some(listener) = &self.listener else {
                return Ok(());
            };
            let stream = match accept_with(listener, SocketFlags::NONBLOCK | SocketFlags::CLOEXEC) {
                Ok(stream) => stream,
                Err(Errno::INTR | Errno::CONNABORTED) => continue,
                Err(Errno::AGAIN) => return Ok(()),
                // E.g., `EMFILE`: the client stays queued, and the listener
                // readable.
                Err(_) => {
                    epoll::delete(epoll, listener)?;
                    self.accept_retry = Some(now.checked_add(ACCEPT_RETRY).unwrap_or(now));
                    return Ok(());
                }
            };
            if host_connections >= MAX_HOST_CONNECTIONS
                || self.handshakes.len() + self.requests.len() >= MAX_PENDING
            {
                continue;
            }
            let Ok(token) = self.register(epoll, &stream) else {
                continue;
            };
            self.handshakes
                .insert(token, Handshake { stream, deadline });
            host_connections += 1;
        }
        Ok(())
    }

    /// Watches the listener again once its accept retry is due.
    fn resume_accepts(&mut self, epoll: &OwnedFd, now: LinuxInstant) -> IoResult<()> {
        if let (Some(listener), Some(retry)) = (&self.listener, self.accept_retry)
            && now >= retry
        {
            epoll::add(
                epoll,
                listener,
                epoll::EventData::new_u64(LISTENER_TOKEN),
                epoll::EventFlags::IN,
            )?;
            self.accept_retry = None;
        }
        Ok(())
    }

    /// Handles the thread's `events` (tokens), with the bridge's lock held:
    /// expires late handshakes, takes in the host clients with
    /// `handshake_timeout` to write their line, and advances handshakes; at
    /// the time `now` gives once the lock is held, and again for each
    /// handshake it would admit.
    fn handle_events(
        &mut self,
        epoll: &OwnedFd,
        wake: &OwnedFd,
        events: impl IntoIterator<Item = u64>,
        now: &dyn Fn() -> LinuxInstant,
        handshake_timeout: Duration,
    ) -> IoResult<()> {
        let locked = now();
        self.expire_handshakes(locked);
        self.resume_accepts(epoll, locked)?;
        for token in events {
            match token {
                WAKE_TOKEN => drain(wake)?,
                LISTENER_TOKEN => self.accept(epoll, locked, handshake_timeout)?,
                token => self.advance_handshake(token, now),
            }
        }
        Ok(())
    }

    /// Reads the handshake of the host client registered as `token`, if any,
    /// once it has its line, unless it is late at `now()`, sampled right
    /// before admitting it: then its request waits for the provider, or it
    /// is closed.
    fn advance_handshake(&mut self, token: u64, now: &dyn Fn() -> LinuxInstant) {
        let Some(handshake) = self.handshakes.get(&token) else {
            return;
        };
        // Sampled before the peek: a client that ends its line after this is
        // seen ending by the next event.
        let ended = poll_now(&handshake.stream)
            .intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR);
        let mut line = [0; MAX_HANDSHAKE];
        let peeked = retry(|| {
            recv(
                &handshake.stream,
                &mut line,
                RecvFlags::PEEK | RecvFlags::DONTWAIT,
            )
        });
        let end = match peeked {
            Err(Errno::AGAIN) => return,
            Ok((len, _)) if len > 0 => match line[..len].iter().position(|&byte| byte == b'\n') {
                Some(newline) => newline + 1,
                // The rest may come, unless the client ended.
                None if len < MAX_HANDSHAKE && !ended => return,
                // Too long, or ended.
                None => {
                    self.handshakes.remove(&token);
                    return;
                }
            },
            // The client closed, or failed, first.
            _ => {
                self.handshakes.remove(&token);
                return;
            }
        };
        let Some(Handshake { stream, deadline }) = self.handshakes.remove(&token) else {
            return;
        };
        if now() >= deadline {
            return;
        }
        // Exactly the line: what follows is the connection's.
        let mut consumed = 0;
        while consumed < end {
            match retry(|| recv(&stream, &mut line[consumed..end], RecvFlags::DONTWAIT)) {
                Ok((len, _)) if len > 0 => consumed += len,
                _ => return,
            }
        }
        let Some(guest_port) = parse_connect(&line[..end - 1]) else {
            return;
        };
        let id = ConnectionId {
            guest_port,
            host_port: self.host_port(),
        };
        self.connections.insert(id, Connection::Requested(stream));
        self.requests.push_back(id);
    }

    /// Closes the host clients whose handshake is late.
    fn expire_handshakes(&mut self, now: LinuxInstant) {
        self.handshakes
            .retain(|_, handshake| handshake.deadline > now);
    }

    /// The earliest handshake deadline, or accept retry.
    fn next_deadline(&self) -> Option<LinuxInstant> {
        self.handshakes
            .values()
            .map(|handshake| handshake.deadline)
            .chain(self.accept_retry)
            .min()
    }

    /// The next host port no connection uses.
    fn host_port(&mut self) -> u32 {
        loop {
            let port = self.next_host_port;
            self.next_host_port = if port >= VMADDR_PORT_ANY - 1 {
                FIRST_HOST_PORT
            } else {
                port + 1
            };
            if !self.connections.keys().any(|id| id.host_port == port) {
                return port;
            }
        }
    }

    fn stream(&self, id: ConnectionId) -> Option<&OwnedFd> {
        match self.connections.get(&id) {
            Some(Connection::Live { stream, .. }) => Some(stream),
            _ => None,
        }
    }
}

/// The port of a `CONNECT <port>` line, without its newline.
fn parse_connect(line: &[u8]) -> Option<u32> {
    let port = line.strip_prefix(b"CONNECT ")?;
    if port.is_empty() || !port.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(port).ok()?.parse().ok()
}

/// `f`, again while interrupted.
fn retry<T>(mut f: impl FnMut() -> rustix::io::Result<T>) -> rustix::io::Result<T> {
    loop {
        match f() {
            Err(Errno::INTR) => {}
            result => return result,
        }
    }
}

/// Adds one to the eventfd `wake`.
fn signal(wake: &OwnedFd) -> IoResult<()> {
    let value = 1_u64.to_ne_bytes();
    match retry(|| write(wake, &value)) {
        Ok(length) if length == value.len() => Ok(()),
        Ok(_) => Err(Error::new(
            ErrorKind::WriteZero,
            "eventfd wake was truncated",
        )),
        // A saturated counter is readable already.
        Err(Errno::AGAIN) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Resets the eventfd `wake`.
fn drain(wake: &OwnedFd) -> IoResult<()> {
    let mut value = [0; size_of::<u64>()];
    match retry(|| read(wake, &mut value)) {
        Ok(length) if length == value.len() => Ok(()),
        Ok(_) => Err(Errno::IO.into()),
        Err(Errno::AGAIN) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// The stream's state, without waiting.
fn poll_now(stream: &OwnedFd) -> PollFlags {
    let mut fds = [PollFd::new(
        stream,
        PollFlags::IN | PollFlags::OUT | PollFlags::RDHUP,
    )];
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    match retry(|| poll(&mut fds, Some(&now))) {
        Ok(_) => fds[0].revents(),
        Err(_) => PollFlags::ERR,
    }
}

/// Whether data waits to be read on `stream`.
fn has_data(stream: &OwnedFd) -> bool {
    ioctl_fionread(stream).is_ok_and(|len| len > 0)
}

/// Whether `stream` is shut down both ways (`POLLHUP`), by either end, and
/// read.
fn ended_and_read(stream: &OwnedFd) -> bool {
    poll_now(stream).contains(PollFlags::HUP) && !has_data(stream)
}

impl Vsock for Bridge {
    fn guest_cid(&self) -> u64 {
        self.guest_cid.into()
    }

    fn take_request(&self) -> Option<ConnectionId> {
        self.lock().requests.pop_front()
    }

    fn accept(&self, id: ConnectionId) -> bool {
        let mut state = self.lock();
        let stream = match state.connections.remove(&id) {
            Some(Connection::Requested(stream)) => stream,
            Some(other) => {
                state.connections.insert(id, other);
                return false;
            }
            None => return false,
        };
        // A new stream has room for the line; if the client is gone, there
        // is nothing to accept.
        let reply = format!("OK {}\n", id.host_port);
        let sent = retry(|| {
            send(
                &stream,
                reply.as_bytes(),
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            )
        });
        if sent.is_ok_and(|sent| sent == reply.len()) {
            state.connections.insert(
                id,
                Connection::Live {
                    stream,
                    from_host: true,
                },
            );
            true
        } else {
            false
        }
    }

    fn refuse(&self, id: ConnectionId) {
        let mut state = self.lock();
        if matches!(state.connections.get(&id), Some(Connection::Requested(_))) {
            state.connections.remove(&id);
        }
    }

    fn connect(&self, id: ConnectionId) -> bool {
        let mut state = self.lock();
        if state.stopped || state.connections.contains_key(&id) {
            return false;
        }
        let connection = match self.connect_host(&mut state, id.host_port) {
            Ok(stream) => Connection::Live {
                stream,
                from_host: false,
            },
            Err(_) => Connection::Failed,
        };
        state.connections.insert(id, connection);
        drop(state);
        self.wake();
        true
    }

    fn connect_state(&self, id: ConnectionId) -> ConnectState {
        let mut state = self.lock();
        match state.connections.get(&id) {
            Some(Connection::Live { .. } | Connection::Closed { .. }) => ConnectState::Established,
            Some(Connection::Failed) => {
                state.connections.remove(&id);
                ConnectState::Failed
            }
            Some(Connection::Requested(_)) | None => ConnectState::Failed,
        }
    }

    fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
        let mut state = self.lock();
        let stream = state.stream(id)?;
        if output.is_empty() {
            return Some(0);
        }
        let read = match retry(|| recv(stream, &mut *output, RecvFlags::DONTWAIT)) {
            Ok((0, _)) => None,
            Ok((len, _)) => Some(len),
            Err(Errno::AGAIN) => Some(0),
            // E.g., `ECONNRESET`: the host closed with data unread.
            Err(_) => None,
        };
        // Its end may have been seen before this drained it.
        if read != Some(0) && ended_and_read(stream) {
            state.reclaim = true;
        }
        read
    }

    fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
        let state = self.lock();
        let stream = state.stream(id)?;
        match retry(|| send(stream, bytes, SendFlags::NOSIGNAL | SendFlags::DONTWAIT)) {
            Ok(len) => Some(len),
            Err(Errno::AGAIN) => Some(0),
            // E.g., `EPIPE`: the host shut down receiving, or closed.
            Err(_) => None,
        }
    }

    fn status(&self, id: ConnectionId) -> ConnectionStatus {
        let state = self.lock();
        let Some(stream) = state.stream(id) else {
            return ConnectionStatus::ENDED;
        };
        let events = poll_now(stream);
        ConnectionStatus {
            readable: has_data(stream),
            host_sending_ended: events
                .intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR),
            writable: events.intersects(PollFlags::OUT | PollFlags::HUP | PollFlags::ERR),
        }
    }

    fn shutdown_sending(&self, id: ConnectionId) {
        if let Some(stream) = self.lock().stream(id) {
            let _ = shutdown(stream, Shutdown::Write);
        }
    }

    fn shutdown_receiving(&self, id: ConnectionId) {
        if let Some(stream) = self.lock().stream(id) {
            let _ = shutdown(stream, Shutdown::Read);
        }
    }

    fn close(&self, id: ConnectionId) {
        let mut state = self.lock();
        let Some(Connection::Live { stream, from_host }) = state.connections.remove(&id) else {
            return;
        };
        let _ = shutdown(&stream, Shutdown::Both);
        // Unread data would reset the host's end.
        let mut scratch = [0; 4096];
        let mut dropped = 0;
        while dropped < MAX_CLOSE_DRAIN {
            match retry(|| recv(&stream, &mut scratch, RecvFlags::DONTWAIT)) {
                Ok((len, _)) if len > 0 => dropped += len,
                _ => break,
            }
        }
        state
            .connections
            .insert(id, Connection::Closed { from_host });
        drop(state);
        drop(stream);
        self.wake();
    }

    fn is_closed(&self, id: ConnectionId) -> bool {
        self.lock().stream(id).is_none_or(ended_and_read)
    }

    fn forget(&self, id: ConnectionId) {
        // Dropping a stream with unread data resets the host's end.
        let connection = self.lock().connections.remove(&id);
        drop(connection);
    }

    fn take_backlog(&self) -> bool {
        let mut state = self.lock();
        // Requests not yet taken are a level, not an edge: the caller
        // repolls while any wait.
        let backlog = !state.requests.is_empty() | std::mem::take(&mut state.reclaim);
        drop(state);
        if backlog {
            self.wake();
        }
        backlog
    }

    fn interrupts(&self) -> bool {
        true
    }
}

/// The thread: serves the bridge until it stops; if serving fails, logs
/// why and stops it.
fn run(bridge: &Bridge, provider: &VsockDeviceProvider<LinuxInstant>) {
    if let Err(error) = serve(bridge, provider) {
        std::eprintln!("hybrid vsock bridge failed: {error}");
        bridge.stop();
        final_poll(provider);
    }
}

/// Waits for the host's streams, the next deadline (the provider's, a
/// handshake's, or an accept retry), or a wakeup; then expires late
/// handshakes, takes in the host clients, and polls the provider; until the
/// bridge stops.
fn serve(bridge: &Bridge, provider: &VsockDeviceProvider<LinuxInstant>) -> IoResult<()> {
    let mut events = Vec::with_capacity(MAX_EVENTS);
    loop {
        let deadline = {
            let state = bridge.lock();
            if state.stopped {
                return Ok(());
            }
            state.next_deadline()
        };
        let deadline = deadline.into_iter().chain(provider.next_deadline()).min();
        let now = LinuxTimeProvider.now();
        // Past `Timespec`'s range: forever.
        let timeout =
            deadline.and_then(|deadline| Timespec::try_from(deadline.duration_since(&now)).ok());
        events.clear();
        match epoll::wait(&bridge.epoll, spare_capacity(&mut events), timeout.as_ref()) {
            Ok(_) | Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(test)]
        bridge
            .wakeups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut state = bridge.lock();
        if state.stopped {
            return Ok(());
        }
        state.handle_events(
            &bridge.epoll,
            &bridge.wake,
            events.iter().map(|event| event.data.u64()),
            &|| LinuxTimeProvider.now(),
            bridge.handshake_timeout,
        )?;
        drop(state);
        provider.poll();
    }
}

/// The provider's polls after the bridge stopped, which publish every
/// socket's end: until the provider has settled (no poll is due after one),
/// sleeping until the deadline it reports between them. A guest operation
/// in flight holds the provider's lock against a poll, so this waits for it
/// to end.
fn final_poll(provider: &VsockDeviceProvider<LinuxInstant>) {
    loop {
        provider.poll();
        let Some(deadline) = provider.next_deadline() else {
            return;
        };
        thread::sleep(deadline.duration_since(&LinuxTimeProvider.now()));
    }
}

#[cfg(test)]
mod tests;
