// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hybrid vsock: the broker's vsock sockets bridged to host Unix stream
//! sockets, as Firecracker's and Cloud Hypervisor's hybrid vsock, which
//! Kata's runtime speaks (`hvsock://PATH:PORT`). [`HybridVsock`] runs
//! [`VsockTransportProvider`] on a [`VsockTransport`] bridge of host Unix
//! sockets, which one thread polls.
//!
//! - **Paths.** `PATH`'s directory is resolved once, at start, to an
//!   absolute canonical path, which holds `PATH` and every `PATH_P`.
//! - **Host to guest.** The bridge listens on `PATH`, which it creates. A
//!   client writes `CONNECT <port>\n` (at most [`MAX_HANDSHAKE`] bytes); if
//!   the guest's listener on that port has room, the bridge assigns a host
//!   port (from 2^30, skipping those in use), writes `OK <host port>\n`, and
//!   the stream is the connection, starting after the newline. Otherwise, or
//!   on a malformed, long or late ([`HANDSHAKE_TIMEOUT`]) line, the stream is
//!   closed.
//! - **Guest to host.** A connect to host port `P` connects to `PATH_P`; if
//!   that fails (missing, not listening, backlog full), the guest's connect
//!   fails with `ECONNRESET`, as when a VMM resets it.
//! - **Data** moves straight between the guest's socket and the stream,
//!   whose buffers hold it. A guest's close shuts the stream down, drops
//!   unread host data (so the host reads EOF rather than a reset), and
//!   closes it: nothing lingers.
//! - **No half-close**, as Firecracker's, Cloud Hypervisor's and
//!   vhost-device-vsock's hybrid vsock: the host's EOF, reset or error ends
//!   the connection both ways (the guest reads what arrived, then EOF, and
//!   its sends fail; the host reads what the guest sent, then EOF), and a
//!   guest's shutdown of one direction is not forwarded: only its shutdown
//!   of both, or its close, ends the stream.
//! - **Thread.** It waits with `epoll` for the listener, the streams, and an
//!   eventfd that operations write when the provider needs a poll it would
//!   not otherwise get, and polls the provider after any event or at its
//!   deadline.
//! - **Lifetime.** Dropping [`HybridVsock`] stops the bridge, for good:
//!   guest connects fail with `ECONNRESET`, host requests are refused, streams
//!   close, a last poll publishes each socket's end (waiting for guest
//!   operations in flight), and `PATH` is removed if still the bridge's
//!   socket. Guest listeners stay listening, as a Linux vsock listener whose
//!   host never connects. A failing thread logs why and stops the bridge the
//!   same way, but `PATH` stays until the drop.
//! - **Trust.** Host clients' input is untrusted (for robustness; see
//!   [`litebox_broker_core::vsock_socket`]): handshakes are bounded in
//!   length, number ([`MAX_PENDING`]) and time, and host connections, from
//!   accept until the provider forgets them, by [`MAX_HOST_CONNECTIONS`];
//!   beyond either, new clients are closed at once. The guest's connections
//!   are bounded by the socket quota. An accept that fails other than
//!   transiently (e.g., out of descriptors) pauses watching `PATH` rather
//!   than spin.
//! - **Access control.** Anyone who can connect to `PATH` reaches the
//!   guest's listeners, and anyone who can create `PATH_P` gets the guest's
//!   connects to port `P`, so the umask (`PATH`'s mode) and `PATH`'s
//!   directory, which must be writable only by the broker's user, are the
//!   access control. Removing `PATH` (an identity check, then an unlink) and
//!   connecting to `PATH_P` are safe only if no other process changes
//!   entries in that directory or its ancestors while the bridge runs. `P`
//!   is a decimal `u32`, so a guest cannot name a path outside it.
//! - **Locks.** The provider's, then the bridge's (each [`VsockTransport`]
//!   call); the thread never takes the provider's while holding the bridge's.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use litebox_broker_core::vsock_socket::VsockProvider;
use litebox_broker_core::vsock_socket::transport::{
    ConnectState, ConnectionId, ConnectionStatus, VsockTransport, VsockTransportProvider,
};
use litebox_broker_protocol::vsock_socket::{VsockCid, VsockPort};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use rustix::buffer::spare_capacity;
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, epoll, eventfd, poll};
use rustix::io::{Errno, ioctl_fionread, read, write};
use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, Shutdown, SocketAddrUnix, SocketFlags, SocketType,
    accept_with, bind, connect, listen, recv, send, shutdown, socket_with, sockopt,
};

use litebox_broker_platform_linux_userland::{LinuxInstant, LinuxTimeProvider};

/// The longest handshake line, with its newline.
pub const MAX_HANDSHAKE: usize = 32;

/// How long a host client has to write its handshake line.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Host clients writing their handshake or waiting for the guest's listener.
pub const MAX_PENDING: usize = 32;

/// Host clients' connections at once, from accepting the client until the
/// provider forgets the connection.
pub const MAX_HOST_CONNECTIONS: usize = 128;

/// The guest's CID unless configured otherwise: the first unreserved one.
pub const DEFAULT_GUEST_CID: VsockCid = VsockCid(3);

/// Whether `cid` can be a guest's: neither reserved (0 to 2) nor
/// [`VsockCid::ANY`].
#[must_use]
pub fn is_guest_cid(cid: VsockCid) -> bool {
    cid > VsockCid::HOST && cid != VsockCid::ANY
}

/// The first host port the bridge assigns to a host client's connection.
const FIRST_HOST_PORT: u32 = 1 << 30;

/// Host clients accepted per wakeup.
const MAX_ACCEPTS: usize = 64;

/// How long the bridge stops watching `PATH` after an accept failed other
/// than transiently.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

const LISTEN_BACKLOG: i32 = 128;

/// Bytes of a closed connection's unread data dropped, so the host reads to
/// EOF rather than a reset; with more, the host gets a reset.
const MAX_CLOSE_DRAIN: usize = 1 << 20;

/// The longest Unix socket path, without its NUL.
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

/// The broker's vsock sockets bridged to host Unix sockets (see the
/// [module](self) docs); dropping it stops the bridge.
pub struct HybridVsock {
    provider: Arc<VsockTransportProvider<LinuxInstant>>,
    bridge: Arc<Bridge>,
    thread: Option<JoinHandle<()>>,
    /// Dropped after the thread ends.
    path: BoundPath,
}

impl HybridVsock {
    /// Starts bridging a guest with CID `guest_cid` at `path`, which must
    /// not exist, in a directory writable only by the broker's user; `seed`
    /// (e.g., from a CSPRNG) starts the ephemeral ports.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a CID that is not a guest's ([`is_guest_cid`]) or a
    /// path with no file name or too long for `PATH_P`; `AddrInUse` if `path`
    /// exists; else the error resolving its directory, creating the listener,
    /// or spawning the thread. Errors but the CID's name the path.
    pub fn start(path: &Path, guest_cid: VsockCid, seed: u64) -> IoResult<Self> {
        Self::start_with(path, guest_cid, seed, HANDSHAKE_TIMEOUT)
    }

    fn start_with(
        path: &Path,
        guest_cid: VsockCid,
        seed: u64,
        handshake_timeout: Duration,
    ) -> IoResult<Self> {
        if !is_guest_cid(guest_cid) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("vsock CID {} is not a guest's", guest_cid.0),
            ));
        }
        let path = resolve(path).map_err(|error| named(error, path))?;
        let (bridge, bound) = Bridge::bind(&path, guest_cid, handshake_timeout)
            .map_err(|error| named(error, &path))?;
        let bridge = Arc::new(bridge);
        let provider = Arc::new(VsockTransportProvider::new(
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

    /// The provider to back the broker's vsock sockets with, until this is
    /// dropped.
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
            .field("guest_cid", &self.bridge.guest_cid.0)
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

/// `PATH`, as the bridge bound it: removed when dropped if still that socket
/// (see the module's access control).
struct BoundPath {
    path: PathBuf,
    /// Its device and inode, right after the bind.
    identity: (u64, u64),
}

impl BoundPath {
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

fn named(error: Error, path: &Path) -> Error {
    Error::new(
        error.kind(),
        format!("hybrid vsock {}: {error}", path.display()),
    )
}

fn port_path(path: &Path, port: VsockPort) -> PathBuf {
    let mut path = path.as_os_str().to_owned();
    path.push(format!("_{}", port.0));
    path.into()
}

/// The provider's [`VsockTransport`]: the host's Unix streams, by connection.
struct Bridge {
    /// `PATH`, in its directory's canonical path.
    path: PathBuf,
    guest_cid: VsockCid,
    handshake_timeout: Duration,
    epoll: OwnedFd,
    wake: OwnedFd,
    state: Mutex<State>,
    #[cfg(test)]
    wakeups: std::sync::atomic::AtomicU64,
}

struct State {
    /// Set once, by [`Bridge::stop`]: no stream is made after.
    stopped: bool,
    /// `None` once stopped.
    listener: Option<OwnedFd>,
    /// When the thread watches the listener again, after an accept failed.
    accept_retry: Option<LinuxInstant>,
    next_token: u64,
    /// Host clients writing their handshake, by epoll token.
    handshakes: HashMap<u64, Handshake>,
    requests: VecDeque<ConnectionId>,
    connections: BTreeMap<ConnectionId, Connection>,
    next_host_port: u32,
    /// A call saw the host end a connection, or drained one it ended, so the
    /// provider must poll to forget it once read.
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
    Live(Live),
    /// A guest's connect that failed.
    Failed,
    /// Closed by the guest.
    Closed { from_host: bool },
}

impl Connection {
    fn is_host_initiated(&self) -> bool {
        match self {
            Self::Requested(_) => true,
            Self::Live(Live { from_host, .. }) | Self::Closed { from_host } => *from_host,
            Self::Failed => false,
        }
    }
}

struct Live {
    stream: OwnedFd,
    from_host: bool,
    /// The host ended the connection (see [`Live::end`]).
    ended: bool,
}

impl Live {
    fn new(stream: OwnedFd, from_host: bool) -> Self {
        Self {
            stream,
            from_host,
            ended: false,
        }
    }

    /// Ends the connection both ways once the host's end of sending, a reset
    /// or an error is seen: the guest's sends fail from then on, and the
    /// stream's sending side is shut down, so the host reads what the guest
    /// sent, then EOF.
    fn end(&mut self) {
        if !self.ended {
            self.ended = true;
            let _ = shutdown(&self.stream, Shutdown::Write);
        }
    }

    /// Whether the host ended the connection; ends it if just now.
    fn check_ended(&mut self) -> bool {
        if !self.ended
            && poll_now(&self.stream).intersects(PollFlags::RDHUP | PollFlags::HUP | PollFlags::ERR)
        {
            self.end();
        }
        self.ended
    }

    /// Ended, and its data read: the provider can forget it.
    fn ended_and_read(&mut self) -> bool {
        self.check_ended() && !has_data(&self.stream)
    }
}

impl Bridge {
    fn bind(
        path: &Path,
        guest_cid: VsockCid,
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

    fn wake(&self) {
        if let Err(error) = signal(&self.wake) {
            std::eprintln!("hybrid vsock bridge wakeup failed: {error}");
        }
    }

    /// Connects to `PATH_P` and registers the stream with the thread.
    fn connect_host(&self, state: &mut State, port: VsockPort) -> IoResult<OwnedFd> {
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

    /// Stops bridging for good, closing every stream and the listener.
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

    fn register(&mut self, epoll: &OwnedFd, stream: &OwnedFd) -> IoResult<u64> {
        // Every stream the bridge reads comes here first. Urgent (`MSG_OOB`)
        // data is read inline, as `FIONREAD`, which `status` relies on,
        // counts it.
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

    /// What [`MAX_HOST_CONNECTIONS`] bounds.
    fn host_connections(&self) -> usize {
        self.handshakes.len()
            + self
                .connections
                .values()
                .filter(|connection| connection.is_host_initiated())
                .count()
    }

    /// Accepts host clients, closing them at once beyond [`MAX_PENDING`] or
    /// [`MAX_HOST_CONNECTIONS`]; after an accept fails other than
    /// transiently, stops watching the listener for [`ACCEPT_RETRY`].
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

    /// Handles the thread's `events` (tokens) under the bridge's lock,
    /// sampling `now` once locked and again before admitting each handshake.
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

    /// Reads the handshake of the client registered as `token` once its line
    /// is complete, queuing its request unless malformed or late at `now()`.
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

    fn expire_handshakes(&mut self, now: LinuxInstant) {
        self.handshakes
            .retain(|_, handshake| handshake.deadline > now);
    }

    fn next_deadline(&self) -> Option<LinuxInstant> {
        self.handshakes
            .values()
            .map(|handshake| handshake.deadline)
            .chain(self.accept_retry)
            .min()
    }

    /// The next host port no connection uses.
    fn host_port(&mut self) -> VsockPort {
        loop {
            let port = VsockPort(self.next_host_port);
            self.next_host_port = if port.0 >= VsockPort::ANY.0 - 1 {
                FIRST_HOST_PORT
            } else {
                port.0 + 1
            };
            if !self.connections.keys().any(|id| id.host_port == port) {
                return port;
            }
        }
    }

    /// Connection `id`, if live; a connection it finds the host ended asks
    /// for a poll to forget it.
    fn live(&mut self, id: ConnectionId) -> Option<&mut Live> {
        let Some(Connection::Live(live)) = self.connections.get_mut(&id) else {
            return None;
        };
        if !live.ended && live.check_ended() {
            self.reclaim = true;
        }
        Some(live)
    }
}

/// The port of a `CONNECT <port>` line, without its newline.
fn parse_connect(line: &[u8]) -> Option<VsockPort> {
    let port = line.strip_prefix(b"CONNECT ")?;
    if port.is_empty() || !port.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(port).ok()?.parse().ok().map(VsockPort)
}

fn retry<T>(mut f: impl FnMut() -> rustix::io::Result<T>) -> rustix::io::Result<T> {
    loop {
        match f() {
            Err(Errno::INTR) => {}
            result => return result,
        }
    }
}

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

fn drain(wake: &OwnedFd) -> IoResult<()> {
    let mut value = [0; size_of::<u64>()];
    match retry(|| read(wake, &mut value)) {
        Ok(length) if length == value.len() => Ok(()),
        Ok(_) => Err(Errno::IO.into()),
        Err(Errno::AGAIN) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

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

fn has_data(stream: &OwnedFd) -> bool {
    ioctl_fionread(stream).is_ok_and(|len| len > 0)
}

impl VsockTransport for Bridge {
    fn guest_cid(&self) -> u64 {
        self.guest_cid.0.into()
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
        let reply = format!("OK {}\n", id.host_port.0);
        let sent = retry(|| {
            send(
                &stream,
                reply.as_bytes(),
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            )
        });
        if sent.is_ok_and(|sent| sent == reply.len()) {
            state
                .connections
                .insert(id, Connection::Live(Live::new(stream, true)));
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
            Ok(stream) => Connection::Live(Live::new(stream, false)),
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
            Some(Connection::Live(_) | Connection::Closed { .. }) => ConnectState::Established,
            Some(Connection::Failed) => {
                state.connections.remove(&id);
                ConnectState::Failed
            }
            Some(Connection::Requested(_)) | None => ConnectState::Failed,
        }
    }

    fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
        let mut state = self.lock();
        let live = state.live(id)?;
        if output.is_empty() {
            return Some(0);
        }
        let read = match retry(|| recv(&live.stream, &mut *output, RecvFlags::DONTWAIT)) {
            Ok((0, _)) => None,
            Ok((len, _)) => Some(len),
            // Ended: nothing more is read.
            Err(Errno::AGAIN) if live.ended => None,
            Err(Errno::AGAIN) => Some(0),
            // E.g., `ECONNRESET`: the host closed with data unread.
            Err(_) => None,
        };
        if read.is_none() {
            live.end();
        }
        // Its end may have been seen before this drained it.
        if read != Some(0) && live.ended_and_read() {
            state.reclaim = true;
        }
        read
    }

    fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
        let mut state = self.lock();
        let live = state.live(id)?;
        if live.ended {
            return None;
        }
        match retry(|| {
            send(
                &live.stream,
                bytes,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            )
        }) {
            Ok(len) => Some(len),
            Err(Errno::AGAIN) => Some(0),
            // E.g., `EPIPE`: the host shut down receiving.
            Err(_) => {
                live.end();
                state.reclaim = true;
                None
            }
        }
    }

    fn status(&self, id: ConnectionId) -> ConnectionStatus {
        let mut state = self.lock();
        let Some(live) = state.live(id) else {
            return ConnectionStatus::ENDED;
        };
        ConnectionStatus {
            readable: has_data(&live.stream),
            host_sending_ended: live.ended,
            writable: live.ended || poll_now(&live.stream).contains(PollFlags::OUT),
        }
    }

    // Hybrid vsock has no half-close: the host sees only the guest's close.
    fn shutdown_sending(&self, _id: ConnectionId) {}

    fn shutdown_receiving(&self, _id: ConnectionId) {}

    fn close(&self, id: ConnectionId) {
        let mut state = self.lock();
        // Others stay until forgotten, e.g., one closed by an earlier call.
        let (stream, from_host) = match state.connections.remove(&id) {
            Some(Connection::Live(Live {
                stream, from_host, ..
            })) => (stream, from_host),
            Some(other) => {
                state.connections.insert(id, other);
                return;
            }
            None => return,
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
        self.lock().live(id).is_none_or(Live::ended_and_read)
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

/// The thread: serves the bridge until it stops, or stops it on failure.
fn run(bridge: &Bridge, provider: &VsockTransportProvider<LinuxInstant>) {
    if let Err(error) = serve(bridge, provider) {
        std::eprintln!("hybrid vsock bridge failed: {error}");
        bridge.stop();
        final_poll(provider);
    }
}

/// Until the bridge stops, waits for an event or the next deadline (the
/// provider's, a handshake's, or an accept retry), handles it, and polls the
/// provider.
fn serve(bridge: &Bridge, provider: &VsockTransportProvider<LinuxInstant>) -> IoResult<()> {
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

/// Polls the provider after the bridge stopped, publishing every socket's
/// end, until no poll is due; it waits for guest operations in flight, which
/// hold the provider's lock.
fn final_poll(provider: &VsockTransportProvider<LinuxInstant>) {
    loop {
        provider.poll();
        let Some(deadline) = provider.next_deadline() else {
            return;
        };
        thread::sleep(deadline.duration_since(&LinuxTimeProvider.now()));
    }
}

#[cfg(test)]
mod tests {
    //! The bridge, with the provider on it, through the broker core as runner
    //! processes use it, and the host's ends as `std` Unix streams.

    use super::*;
    use std::cell::Cell;
    use std::io::{Read as _, Write as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::Ordering;
    use std::sync::{Barrier, Condvar};
    use std::time::Instant;

    use litebox_broker_core::readiness::ReadinessSink;
    use litebox_broker_core::socket::PlatformStreamReceive;
    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::vsock_socket as core_vsock;
    use litebox_broker_core::{
        BrokerError, BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
        Result as BrokerResult, VsockPolicy,
    };
    use litebox_broker_protocol::ObjectHandle;
    use litebox_broker_protocol::fs::FileOpenFlags;
    use litebox_broker_protocol::readiness::ReadinessFlags;
    use litebox_broker_protocol::socket::{
        SendFlags as GuestSendFlags, ShutdownMode, SocketConnectionStatus, SocketError,
        SocketOutcome,
    };
    use litebox_broker_protocol::vsock_socket::{CreateVsockSocketRequest, VsockAddress};
    use litebox_platform::buffer::{Buffer, Fault, RawBytes, WriteBuffer};

    const GUEST_CID: VsockCid = DEFAULT_GUEST_CID;
    /// The first ephemeral port.
    const SEED: u64 = 50_000;
    const PORT: u32 = 1024;
    /// The longest any wait for the bridge may take.
    const WAIT: Duration = Duration::from_secs(10);

    const READ: ReadinessFlags = ReadinessFlags::READ;
    const WRITE: ReadinessFlags = ReadinessFlags::WRITE;
    const HANGUP: ReadinessFlags = ReadinessFlags::HANGUP;
    const ERROR: ReadinessFlags = ReadinessFlags::ERROR;

    /// Counts readiness publications, and wakes those waiting for one.
    #[derive(Default)]
    struct Sink {
        publications: Mutex<u64>,
        published: Condvar,
    }

    impl Sink {
        fn note(&self) {
            *self.publications.lock().unwrap() += 1;
            self.published.notify_all();
        }
    }

    impl ReadinessSink for Sink {
        fn max_tracked_objects(&self) -> usize {
            usize::MAX
        }

        fn publish(&self, _handle: ObjectHandle, _readiness: ReadinessFlags) -> BrokerResult<()> {
            self.note();
            Ok(())
        }

        fn republish(&self, _handle: ObjectHandle, _readiness: ReadinessFlags) -> BrokerResult<()> {
            self.note();
            Ok(())
        }

        fn retire(&self, _handle: ObjectHandle) {}
    }

    /// A bridge in a temporary directory, its provider in a broker core, and a
    /// guest process.
    struct Fixture {
        path: PathBuf,
        guest: Arc<BrokerProcess>,
        sink: Arc<Sink>,
        /// `None` once stopped.
        vsock: Option<HybridVsock>,
        // Last: the bridge's paths are in it.
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_handshake_timeout(HANDSHAKE_TIMEOUT)
        }

        fn with_handshake_timeout(handshake_timeout: Duration) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vsock");
            let vsock = HybridVsock::start_with(&path, GUEST_CID, SEED, handshake_timeout).unwrap();
            // As the userland broker's with `--vsock-uds`.
            let core = TestBrokerCoreBuilder::new(
                PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
                    .with_vsock_policy(VsockPolicy::any()),
            )
            .with_vsock_provider(vsock.provider())
            .build()
            .unwrap();
            let guest = core
                .create_process(CallerCredential::HostGuaranteed, None)
                .unwrap();
            Self {
                path,
                guest,
                sink: Arc::default(),
                vsock: Some(vsock),
                _dir: dir,
            }
        }

        fn bridge(&self) -> &Bridge {
            &self.vsock.as_ref().expect("the bridge stopped").bridge
        }

        fn connections(&self) -> usize {
            self.bridge().lock().connections.len()
        }

        fn port_path(&self, port: u32) -> PathBuf {
            port_path(&self.path, VsockPort(port))
        }

        /// Waits until `socket` is ready for all of `flags`.
        fn wait(&self, socket: ObjectHandle, flags: ReadinessFlags) -> ReadinessFlags {
            self.wait_for(socket, |readiness| readiness.contains(flags))
        }

        /// Waits until `socket`'s readiness satisfies `ready`.
        fn wait_for(
            &self,
            socket: ObjectHandle,
            ready: impl Fn(ReadinessFlags) -> bool,
        ) -> ReadinessFlags {
            let deadline = Instant::now() + WAIT;
            loop {
                // Read first: a publication after the check is not missed.
                let seen = *self.sink.publications.lock().unwrap();
                let readiness = self.guest.check_readiness(socket).unwrap();
                if ready(readiness) {
                    return readiness;
                }
                let mut publications = self.sink.publications.lock().unwrap();
                while *publications == seen {
                    let left = deadline
                        .checked_duration_since(Instant::now())
                        .unwrap_or_else(|| panic!("{socket:?} still {readiness:?}"));
                    publications = self
                        .sink
                        .published
                        .wait_timeout(publications, left)
                        .unwrap()
                        .0;
                }
            }
        }

        fn socket(&self) -> ObjectHandle {
            let request = CreateVsockSocketRequest {
                socket_type: litebox_broker_protocol::socket::SocketType::Stream,
                flags: FileOpenFlags::NONBLOCKING,
            };
            core_vsock::create(&self.guest, request, self.sink.clone()).unwrap()
        }

        fn listen(&self, port: u32, backlog: u32) -> ObjectHandle {
            let listener = self.socket();
            let address = VsockAddress {
                cid: VsockCid::ANY,
                port: VsockPort(port),
            };
            assert_eq!(
                core_vsock::bind(&self.guest, listener, address).unwrap(),
                SocketOutcome::Completed(())
            );
            assert_eq!(
                core_vsock::listen(&self.guest, listener, backlog).unwrap(),
                SocketOutcome::Completed(())
            );
            listener
        }

        /// Accepts on `listener` once a connection waits; the socket and its
        /// peer's port.
        fn accept(&self, listener: ObjectHandle) -> (ObjectHandle, u32) {
            self.wait(listener, READ);
            let accepted = match core_vsock::accept(
                &self.guest,
                listener,
                FileOpenFlags::NONBLOCKING,
                self.sink.clone(),
            )
            .unwrap()
            {
                SocketOutcome::Completed(accepted) => accepted,
                SocketOutcome::Failed(error) => panic!("accept: {error:?}"),
            };
            assert_eq!(accepted.remote_address.cid, VsockCid::HOST);
            (accepted.handle, accepted.remote_address.port.0)
        }

        /// A socket's connect to the host's `port`, once settled.
        fn connect(&self, port: u32) -> (ObjectHandle, SocketOutcome<SocketConnectionStatus>) {
            let socket = self.socket();
            let address = VsockAddress {
                cid: VsockCid::HOST,
                port: VsockPort(port),
            };
            assert_eq!(
                core_vsock::connect(&self.guest, socket, address).unwrap(),
                SocketOutcome::Completed(SocketConnectionStatus::Connecting)
            );
            self.wait_for(socket, |readiness| {
                readiness.contains(WRITE) || readiness.contains(ERROR)
            });
            let outcome = core_vsock::check_connect(&self.guest, socket).unwrap();
            (socket, outcome)
        }

        fn send(&self, socket: ObjectHandle, bytes: &[u8]) -> BrokerResult<SocketOutcome<usize>> {
            core_vsock::send(&self.guest, socket, &bytes, GuestSendFlags::NONE)
        }

        /// Sends all of `bytes`, waiting for room.
        fn send_all(&self, socket: ObjectHandle, bytes: &[u8]) {
            let mut sent = 0;
            while sent < bytes.len() {
                let end = bytes.len().min(sent + 32 * 1024);
                match self.send(socket, &bytes[sent..end]) {
                    Ok(SocketOutcome::Completed(len)) => sent += len,
                    Err(BrokerError::NonBlockingWouldBlock) => {
                        self.wait(socket, WRITE);
                    }
                    other => panic!("send: {other:?}"),
                }
            }
        }

        /// Receives up to `len` bytes, waiting for some; `None` at EOF.
        fn receive(&self, socket: ObjectHandle, len: usize) -> Option<Vec<u8>> {
            let mut buffer = vec![0; len];
            loop {
                match core_vsock::receive(&self.guest, socket, &mut buffer) {
                    Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(received))) => {
                        buffer.truncate(received);
                        return Some(buffer);
                    }
                    Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream)) => {
                        return None;
                    }
                    Err(BrokerError::NonBlockingWouldBlock) => {
                        self.wait(socket, READ);
                    }
                    other => panic!("receive: {other:?}"),
                }
            }
        }

        fn receive_exact(&self, socket: ObjectHandle, len: usize) -> Vec<u8> {
            let mut received = Vec::with_capacity(len);
            while received.len() < len {
                let chunk = self
                    .receive(socket, (len - received.len()).min(32 * 1024))
                    .expect("end of stream");
                received.extend_from_slice(&chunk);
            }
            received
        }

        fn shutdown(&self, socket: ObjectHandle, mode: ShutdownMode) {
            assert_eq!(
                core_vsock::shutdown(&self.guest, socket, mode).unwrap(),
                SocketOutcome::Completed(())
            );
        }

        fn close(&self, socket: ObjectHandle) {
            self.guest.close_object_reference(socket).unwrap();
        }

        /// A host client connected to `PATH`, without a handshake.
        fn client(&self) -> UnixStream {
            let stream = UnixStream::connect(&self.path).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            stream
        }

        /// A host client that wrote `line`; its stream.
        fn request(&self, line: &[u8]) -> UnixStream {
            let mut stream = self.client();
            stream.write_all(line).unwrap();
            stream
        }

        /// A host client's connection to the guest's listener on `port`; the
        /// client's stream and port.
        fn handshake(&self, port: u32) -> (UnixStream, u32) {
            let mut stream = self.request(format!("CONNECT {port}\n").as_bytes());
            let line = read_line(&mut stream).expect("the bridge closed the stream");
            let host_port = line
                .strip_prefix("OK ")
                .and_then(|port| port.parse().ok())
                .unwrap_or_else(|| panic!("bad reply {line:?}"));
            (stream, host_port)
        }
    }

    /// Waits until `done`, which nothing publishes.
    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < deadline, "never {what}");
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// A line from `stream`, reading no further; `None` at EOF.
    fn read_line(stream: &mut UnixStream) -> Option<String> {
        let mut line = Vec::new();
        let mut byte = [0];
        loop {
            if stream.read(&mut byte).unwrap() == 0 {
                return None;
            }
            if byte[0] == b'\n' {
                return Some(String::from_utf8(line).unwrap());
            }
            line.push(byte[0]);
        }
    }

    /// Asserts the bridge closed `stream`, which reads EOF (or a reset, if the
    /// bridge closed it with data unread or never accepted it).
    fn assert_closed(stream: &mut UnixStream) {
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == ErrorKind::ConnectionReset => {}
            other => panic!("not closed: {other:?}"),
        }
    }

    fn read_to_end(stream: &mut UnixStream) -> Vec<u8> {
        let mut data = Vec::new();
        stream.read_to_end(&mut data).unwrap();
        data
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from((i * 7 + i / 4096) & 0xff).unwrap())
            .collect()
    }

    #[test]
    fn start_checks_the_cid_and_path_and_stop_removes_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vsock");
        for cid in [VsockCid::HOST, VsockCid::ANY] {
            assert!(!is_guest_cid(cid));
            let error = HybridVsock::start(&path, cid, SEED).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidInput, "CID {cid:?}");
        }
        assert!(is_guest_cid(DEFAULT_GUEST_CID));
        let long = dir.path().join("v".repeat(MAX_SOCKET_PATH));
        let error = HybridVsock::start(&long, GUEST_CID, SEED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let error = HybridVsock::start(Path::new("/"), GUEST_CID, SEED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        let missing = dir.path().join("missing").join("vsock");
        let error = HybridVsock::start(&missing, GUEST_CID, SEED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(error.to_string().contains(&*missing.to_string_lossy()));
        assert!(!path.exists());

        let vsock = HybridVsock::start(&path, GUEST_CID, SEED).unwrap();
        let error = HybridVsock::start(&path, GUEST_CID, SEED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AddrInUse);
        assert!(error.to_string().contains(&*path.to_string_lossy()));
        drop(vsock);
        assert!(!path.exists());
        // A path that is not the bridge's is left alone.
        std::fs::write(&path, b"not a socket").unwrap();
        let error = HybridVsock::start(&path, GUEST_CID, SEED).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::AddrInUse);
        assert!(path.exists());
    }

    #[test]
    fn stopping_leaves_a_replaced_path_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vsock");
        let vsock = HybridVsock::start(&path, GUEST_CID, SEED).unwrap();
        std::fs::remove_file(&path).unwrap();
        let _other = UnixListener::bind(&path).unwrap();
        drop(vsock);
        assert!(path.exists());
    }

    /// Changes the working directory: nextest runs each test in its own process.
    #[test]
    fn relative_paths_stay_in_their_directory() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::env::set_current_dir(first.path()).unwrap();
        let vsock = HybridVsock::start(Path::new("vsock"), GUEST_CID, SEED).unwrap();
        std::env::set_current_dir(second.path()).unwrap();
        let host = UnixListener::bind(first.path().join("vsock_7000")).unwrap();
        let id = ConnectionId {
            guest_port: VsockPort(5000),
            host_port: VsockPort(7000),
        };
        assert!(vsock.bridge.connect(id));
        assert_eq!(vsock.bridge.connect_state(id), ConnectState::Established);
        host.accept().unwrap();
        drop(vsock);
        assert!(!first.path().join("vsock").exists());
        assert!(first.path().join("vsock_7000").exists());
    }

    #[test]
    fn host_clients_connect_to_guest_listeners() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        // What follows the line is the connection's.
        let mut first = f.request(b"CONNECT 1024\nhello");
        let (socket, host_port) = f.accept(listener);
        assert!(host_port >= FIRST_HOST_PORT);
        assert_eq!(read_line(&mut first), Some(format!("OK {host_port}")));
        assert_eq!(
            core_vsock::get_name(&f.guest, socket, false).unwrap(),
            Some(VsockAddress {
                cid: GUEST_CID,
                port: VsockPort(PORT)
            })
        );
        assert_eq!(f.receive_exact(socket, 5), b"hello");
        f.send_all(socket, b"world");
        let mut reply = [0; 5];
        first.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"world");

        // The next client has the next port; leading zeros are fine.
        let mut second = f.request(b"CONNECT 0001024\n");
        let (_, next_port) = f.accept(listener);
        assert_eq!(next_port, host_port + 1);
        assert_eq!(read_line(&mut second), Some(format!("OK {next_port}")));
    }

    #[test]
    fn malformed_handshakes_are_closed() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 16);
        // The grammar is `parse_connect`'s (see its test).
        let mut client = f.request(b"CONNECT +1024\n");
        assert_closed(&mut client);
        // A client that ends before its line.
        let mut client = f.request(b"CONNECT 1024");
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert_closed(&mut client);
        assert!(!f.guest.check_readiness(listener).unwrap().contains(READ));
    }

    #[test]
    fn handshake_lines_are_bounded() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let longest = format!("CONNECT {PORT:0>23}\n");
        assert_eq!(longest.len(), MAX_HANDSHAKE);
        let mut client = f.request(longest.as_bytes());
        f.accept(listener);
        assert!(read_line(&mut client).unwrap().starts_with("OK "));
        // One byte more, and no newline in the first MAX_HANDSHAKE.
        let mut client = f.request(format!("CONNECT {PORT:0>24}\n").as_bytes());
        assert_closed(&mut client);
        let mut client = f.request(&[b'C'; MAX_HANDSHAKE]);
        assert_closed(&mut client);
    }

    #[test]
    fn late_handshakes_are_closed() {
        let timeout = Duration::from_millis(300);
        let f = Fixture::with_handshake_timeout(timeout);
        let listener = f.listen(PORT, 4);
        let start = Instant::now();
        let mut late = f.request(b"CONNECT 1024");
        assert_closed(&mut late);
        assert!(start.elapsed() >= timeout);
        let mut silent = f.client();
        assert_closed(&mut silent);
        assert!(!f.guest.check_readiness(listener).unwrap().contains(READ));
    }

    #[test]
    fn handshakes_wait_for_their_line_until_the_client_ends() {
        let mut state = State::new();
        let now = LinuxTimeProvider.now();
        let deadline = now.checked_add(WAIT).unwrap();
        let mut clients = Vec::new();
        for token in [FIRST_STREAM_TOKEN, FIRST_STREAM_TOKEN + 1] {
            let (stream, mut client) = UnixStream::pair().unwrap();
            client.write_all(b"CONNECT 10").unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            state.handshakes.insert(
                token,
                Handshake {
                    stream: stream.into(),
                    deadline,
                },
            );
            clients.push(client);
        }
        state.advance_handshake(FIRST_STREAM_TOKEN, &|| now);
        assert_eq!(state.handshakes.len(), 2);
        // Ended with its line.
        clients[0].write_all(b"24\n").unwrap();
        clients[0].shutdown(std::net::Shutdown::Write).unwrap();
        state.advance_handshake(FIRST_STREAM_TOKEN, &|| now);
        assert_eq!(
            state.requests,
            [ConnectionId {
                guest_port: VsockPort(1024),
                host_port: VsockPort(FIRST_HOST_PORT)
            }]
        );
        // Ended without it.
        clients[1].shutdown(std::net::Shutdown::Write).unwrap();
        state.advance_handshake(FIRST_STREAM_TOKEN + 1, &|| now);
        assert!(state.handshakes.is_empty());
        assert_eq!(state.requests.len(), 1);
        assert_closed(&mut clients[1]);
    }

    #[test]
    fn urgent_data_reads_inline() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (from_host, _) = f.handshake(PORT);
        let (accepted, _) = f.accept(listener);
        let host = UnixListener::bind(f.port_path(5000)).unwrap();
        let (connected, outcome) = f.connect(5000);
        assert_eq!(
            outcome,
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        );
        let (to_host, _) = host.accept().unwrap();
        for (mut stream, socket) in [(from_host, accepted), (to_host, connected)] {
            match rustix::net::send(&stream, b"x", SendFlags::OOB) {
                Ok(_) => {}
                // A kernel without `AF_UNIX` urgent data.
                Err(Errno::OPNOTSUPP) => return,
                Err(error) => panic!("urgent send: {error}"),
            }
            stream.write_all(b"yz").unwrap();
            drop(stream);
            assert_eq!(f.receive_exact(socket, 3), b"xyz");
            assert_eq!(f.receive(socket, 16), None);
        }
        wait_until("reclaimed", || f.connections() == 0);
    }

    /// Adds complete handshakes `(token, deadline)` to `state`; their clients.
    fn complete_handshakes(
        state: &mut State,
        handshakes: &[(u64, LinuxInstant)],
    ) -> Vec<UnixStream> {
        let mut clients = Vec::new();
        for &(token, deadline) in handshakes {
            let (stream, mut client) = UnixStream::pair().unwrap();
            client.write_all(b"CONNECT 1024\n").unwrap();
            client.set_read_timeout(Some(WAIT)).unwrap();
            state.handshakes.insert(
                token,
                Handshake {
                    stream: stream.into(),
                    deadline,
                },
            );
            clients.push(client);
        }
        clients
    }

    #[test]
    fn handshakes_late_by_their_admission_are_rejected() {
        let epoll = epoll::create(epoll::CreateFlags::CLOEXEC).unwrap();
        let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK).unwrap();
        let mut state = State::new();
        let start = LinuxTimeProvider.now();
        let deadline = start.checked_add(Duration::from_secs(1)).unwrap();
        let mut clients = complete_handshakes(
            &mut state,
            &[
                (FIRST_STREAM_TOKEN, deadline),
                (FIRST_STREAM_TOKEN + 1, deadline.checked_add(WAIT).unwrap()),
            ],
        );
        // In time once the lock is held; the first's deadline passes while the
        // thread handles the batch.
        let samples = Cell::new(0);
        let now = || {
            samples.set(samples.get() + 1);
            if samples.get() == 1 { start } else { deadline }
        };
        state
            .handle_events(
                &epoll,
                &wake,
                [FIRST_STREAM_TOKEN, FIRST_STREAM_TOKEN + 1],
                &now,
                HANDSHAKE_TIMEOUT,
            )
            .unwrap();
        assert!(samples.get() > 1);
        assert!(state.handshakes.is_empty());
        // Only the one in time.
        assert_eq!(
            state.requests,
            [ConnectionId {
                guest_port: VsockPort(1024),
                host_port: VsockPort(FIRST_HOST_PORT)
            }]
        );
        assert_closed(&mut clients[0]);
    }

    #[test]
    fn handshakes_late_once_the_lock_is_held_are_rejected() {
        let epoll = epoll::create(epoll::CreateFlags::CLOEXEC).unwrap();
        let wake = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK).unwrap();
        let mut state = State::new();
        let deadline = LinuxTimeProvider.now();
        let mut clients = complete_handshakes(&mut state, &[(FIRST_STREAM_TOKEN, deadline)]);
        // The line came in time, but the thread takes the lock at the deadline.
        state
            .handle_events(
                &epoll,
                &wake,
                [FIRST_STREAM_TOKEN],
                &|| deadline,
                HANDSHAKE_TIMEOUT,
            )
            .unwrap();
        assert!(state.handshakes.is_empty());
        assert!(state.requests.is_empty());
        assert_closed(&mut clients[0]);
    }

    #[test]
    fn requests_without_a_listener_with_room_are_closed() {
        let f = Fixture::new();
        let mut client = f.request(b"CONNECT 2000\n");
        assert_closed(&mut client);
        // A backlog of 0 holds one.
        let listener = f.listen(PORT, 0);
        let (mut first, _) = f.handshake(PORT);
        let mut full = f.request(b"CONNECT 1024\n");
        assert_closed(&mut full);
        let (socket, _) = f.accept(listener);
        let (mut second, _) = f.handshake(PORT);
        f.send_all(socket, b"x");
        let mut byte = [0];
        first.read_exact(&mut byte).unwrap();
        // The guest's close ends the first; the second waits.
        f.close(socket);
        assert_eq!(read_to_end(&mut first), b"");
        let (socket, _) = f.accept(listener);
        f.send_all(socket, b"y");
        second.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"y");
    }

    #[test]
    fn pending_clients_are_bounded() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let mut pending: Vec<_> = (0..MAX_PENDING).map(|_| f.client()).collect();
        // The bridge accepts in order: this one finds MAX_PENDING waiting.
        let mut excess = f.client();
        assert_closed(&mut excess);
        pending[0].write_all(b"CONNECT 1024\n").unwrap();
        f.accept(listener);
        assert!(read_line(&mut pending[0]).unwrap().starts_with("OK "));
    }

    #[test]
    fn host_connections_are_bounded() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4096);
        // None accepted: all wait in the listener's backlog.
        let mut clients: Vec<_> = (0..MAX_HOST_CONNECTIONS)
            .map(|_| f.handshake(PORT).0)
            .collect();
        // Closed at once, before it could write.
        let mut excess = f.client();
        assert_closed(&mut excess);
        // The guest's close of one frees its slot, once the provider forgets it.
        let (socket, _) = f.accept(listener);
        f.close(socket);
        assert_eq!(read_to_end(&mut clients[0]), b"");
        wait_until("freed", || {
            f.bridge().lock().host_connections() < MAX_HOST_CONNECTIONS
        });
        f.handshake(PORT);
    }

    #[test]
    fn requests_beyond_a_poll_s_budget_reach_accept() {
        const CLIENTS: usize = 20;
        let f = Fixture::new();
        let listener = f.listen(PORT, 32);
        // All at once: more than a poll takes.
        let mut clients: Vec<_> = (0..CLIENTS).map(|_| f.request(b"CONNECT 1024\n")).collect();
        for _ in 0..CLIENTS {
            f.accept(listener);
        }
        for client in &mut clients {
            assert!(read_line(client).unwrap().starts_with("OK "));
        }
    }

    #[test]
    fn host_ports_wrap_and_skip_ports_in_use() {
        let mut state = State::new();
        state.next_host_port = VsockPort::ANY.0 - 1;
        state.connections.insert(
            ConnectionId {
                guest_port: VsockPort(PORT),
                host_port: VsockPort(FIRST_HOST_PORT),
            },
            Connection::Failed,
        );
        assert_eq!(state.host_port(), VsockPort(VsockPort::ANY.0 - 1));
        assert_eq!(state.host_port(), VsockPort(FIRST_HOST_PORT + 1));
    }

    #[test]
    fn host_clients_gone_from_a_backlog_end_at_accept() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (stream, _) = f.handshake(PORT);
        drop(stream);
        let (socket, _) = f.accept(listener);
        assert_eq!(f.receive(socket, 16), None);
        // Without another event, or the guest's close.
        wait_until("reclaimed", || f.connections() == 0);
    }

    #[test]
    fn drained_ended_connections_are_reclaimed() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (mut stream, _) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        stream.write_all(b"bye").unwrap();
        drop(stream);
        // A poll saw the end, with the data unread.
        f.wait(socket, READ | HANGUP);
        assert_eq!(f.connections(), 1);
        // Exactly the data, so no read finds the end.
        assert_eq!(f.receive(socket, 3).unwrap(), b"bye");
        wait_until("reclaimed", || f.connections() == 0);
        assert_eq!(f.receive(socket, 16), None);
    }

    #[test]
    fn accept_failures_back_off_and_recover() {
        use rustix::process::{Resource, getrlimit, setrlimit};

        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let client = rustix::net::socket(AddressFamily::UNIX, SocketType::STREAM, None).unwrap();
        let limit = getrlimit(Resource::Nofile);
        // The lowest free descriptor is the next accept's.
        let lowest = rustix::io::dup(&client).unwrap().as_raw_fd();
        let mut lowered = limit;
        lowered.current = Some(u64::try_from(lowest).unwrap());
        setrlimit(Resource::Nofile, lowered).unwrap();
        let before = f.bridge().wakeups.load(Ordering::Relaxed);
        connect(&client, &SocketAddrUnix::new(&f.path).unwrap()).unwrap();
        thread::sleep(Duration::from_millis(500));
        let wakeups = f.bridge().wakeups.load(Ordering::Relaxed) - before;
        setrlimit(Resource::Nofile, limit).unwrap();
        // About one per retry, not a spin.
        assert!(wakeups < 50, "{wakeups} wakeups");
        let mut client = UnixStream::from(client);
        client.set_read_timeout(Some(WAIT)).unwrap();
        client.write_all(b"CONNECT 1024\n").unwrap();
        f.accept(listener);
        assert!(read_line(&mut client).unwrap().starts_with("OK "));
    }

    #[test]
    fn guest_connects_reach_listening_port_paths_only() {
        let f = Fixture::new();
        let (missing, outcome) = f.connect(5000);
        assert_eq!(outcome, SocketOutcome::Failed(SocketError::ConnectionReset));
        assert_eq!(
            core_vsock::take_error(&f.guest, missing).unwrap(),
            Some(SocketError::ConnectionReset)
        );

        let host = UnixListener::bind(f.port_path(5003)).unwrap();
        let (socket, outcome) = f.connect(5003);
        assert_eq!(
            outcome,
            SocketOutcome::Completed(SocketConnectionStatus::Connected)
        );
        assert_eq!(
            core_vsock::get_name(&f.guest, socket, true).unwrap(),
            Some(VsockAddress {
                cid: VsockCid::HOST,
                port: VsockPort(5003)
            })
        );
        let (mut stream, _) = host.accept().unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        f.send_all(socket, b"ping");
        let mut ping = [0; 4];
        stream.read_exact(&mut ping).unwrap();
        assert_eq!(&ping, b"ping");
        stream.write_all(b"pong").unwrap();
        assert_eq!(f.receive_exact(socket, 4), b"pong");
    }

    #[test]
    fn data_moves_both_ways_with_backpressure() {
        const LEN: usize = 4 * 1024 * 1024;
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (stream, _) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        let data = pattern(LEN);
        // Until the host's stream is full, which the host does not read yet.
        let mut sent = 0;
        loop {
            match f.send(socket, &data[sent..sent + 32 * 1024]) {
                Ok(SocketOutcome::Completed(len)) => sent += len,
                Err(BrokerError::NonBlockingWouldBlock) => break,
                other => panic!("send: {other:?}"),
            }
            assert!(sent < LEN, "the host's stream took everything");
        }
        assert!(!f.guest.check_readiness(socket).unwrap().contains(WRITE));
        let host = thread::spawn(move || {
            let mut stream = stream;
            let mut received = vec![0; LEN];
            stream.read_exact(&mut received).unwrap();
            assert!(received == pattern(LEN), "the host received other data");
            stream.write_all(&pattern(LEN)).unwrap();
            stream
        });
        f.send_all(socket, &data[sent..]);
        assert!(
            f.receive_exact(socket, LEN) == pattern(LEN),
            "the guest received other data"
        );
        host.join().unwrap();
    }

    /// Asserts the host's `stream` has no data and no EOF.
    fn assert_open(stream: &mut UnixStream) {
        stream.set_nonblocking(true).unwrap();
        let error = stream.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::WouldBlock);
        stream.set_nonblocking(false).unwrap();
    }

    #[test]
    fn guest_shutdowns_reach_the_host_only_both_ways() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (mut stream, host_port) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        // SHUT_WR: the host reads the data, but no EOF, and still sends.
        f.send_all(socket, b"before");
        f.shutdown(socket, ShutdownMode::Write);
        let mut before = [0; 6];
        stream.read_exact(&mut before).unwrap();
        assert_eq!(&before, b"before");
        assert_open(&mut stream);
        stream.write_all(b"after").unwrap();
        assert_eq!(f.receive_exact(socket, 5), b"after");
        // SHUT_RD: the host's sends still succeed, and the provider drops them.
        f.shutdown(socket, ShutdownMode::Read);
        stream.write_all(b"dropped").unwrap();
        assert_eq!(f.receive(socket, 16), None);
        let id = ConnectionId {
            guest_port: VsockPort(PORT),
            host_port: VsockPort(host_port),
        };
        wait_until("dropped", || {
            f.bridge()
                .lock()
                .live(id)
                .is_some_and(|live| !has_data(&live.stream))
        });
        assert_open(&mut stream);
        // Both ways ends the stream, as a close: the host's writes fail.
        f.shutdown(socket, ShutdownMode::Both);
        assert_eq!(read_to_end(&mut stream), b"");
        assert_eq!(
            stream.write_all(b"late").unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn host_eof_ends_the_connection_both_ways() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (mut stream, _) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        f.send_all(socket, b"guest");
        stream.write_all(b"host").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        // Writable, as a send fails.
        f.wait(socket, READ | WRITE | HANGUP);
        assert_eq!(
            f.send(socket, b"x").unwrap(),
            SocketOutcome::Failed(SocketError::Shutdown)
        );
        // The host reads what the guest sent, then EOF.
        assert_eq!(read_to_end(&mut stream), b"guest");
        assert_eq!(f.receive_exact(socket, 4), b"host");
        assert_eq!(f.receive(socket, 16), None);
        wait_until("reclaimed", || f.connections() == 0);
    }

    #[test]
    fn host_closes_and_resets_end_the_connection() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        // A close after data: the guest reads it, then EOF; sends fail.
        let (mut stream, _) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        stream.write_all(b"bye").unwrap();
        drop(stream);
        f.wait(socket, READ | WRITE | HANGUP);
        assert_eq!(f.receive_exact(socket, 3), b"bye");
        assert_eq!(f.receive(socket, 16), None);
        assert_eq!(
            f.send(socket, b"x").unwrap(),
            SocketOutcome::Failed(SocketError::Shutdown)
        );
        // A reset: the host closes with the guest's data unread.
        let (stream, _) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        f.send_all(socket, b"unread");
        drop(stream);
        f.wait(socket, READ | WRITE | HANGUP);
        assert_eq!(f.receive(socket, 16), None);
        assert_eq!(
            f.send(socket, b"x").unwrap(),
            SocketOutcome::Failed(SocketError::Shutdown)
        );
        // An error: the host shut down receiving, so a send fails, which ends
        // receiving too, after the data that arrived.
        let (stream, _) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        (&stream).write_all(b"host").unwrap();
        stream.shutdown(std::net::Shutdown::Read).unwrap();
        assert_eq!(
            f.send(socket, b"x").unwrap(),
            SocketOutcome::Failed(SocketError::Shutdown)
        );
        assert!(f.guest.check_readiness(socket).unwrap().contains(HANGUP));
        assert_eq!(f.receive_exact(socket, 4), b"host");
        assert_eq!(f.receive(socket, 16), None);
        wait_until("reclaimed", || f.connections() == 0);
    }

    #[test]
    fn guest_closes_leave_the_host_its_data_and_eof() {
        let f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (mut stream, _) = f.handshake(PORT);
        let (socket, _) = f.accept(listener);
        // The guest never reads this, which must not reset the host's end.
        stream.write_all(b"unread").unwrap();
        f.send_all(socket, b"reply");
        f.close(socket);
        assert_eq!(read_to_end(&mut stream), b"reply");
        let error = stream.write_all(b"more").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);

        // A guest's connection too; and its port is free again.
        let host = UnixListener::bind(f.port_path(6000)).unwrap();
        let (socket, _) = f.connect(6000);
        let port = core_vsock::get_name(&f.guest, socket, false)
            .unwrap()
            .unwrap()
            .port;
        let (mut stream, _) = host.accept().unwrap();
        f.send_all(socket, b"done");
        f.close(socket);
        assert_eq!(read_to_end(&mut stream), b"done");
        let rebound = f.socket();
        let address = VsockAddress {
            cid: VsockCid::ANY,
            port,
        };
        let deadline = Instant::now() + WAIT;
        // The provider frees the port at its next poll, which the close wakes.
        while core_vsock::bind(&f.guest, rebound, address).unwrap() != SocketOutcome::Completed(())
        {
            assert!(Instant::now() < deadline, "port {port:?} still in use");
            thread::yield_now();
        }
    }

    #[test]
    fn closed_connections_stay_until_forgotten() {
        // No thread or provider: only these calls change the connections.
        let dir = tempfile::tempdir().unwrap();
        let (bridge, _bound) =
            Bridge::bind(&dir.path().join("vsock"), GUEST_CID, HANDSHAKE_TIMEOUT).unwrap();
        let (stream, _client) = UnixStream::pair().unwrap();
        let id = ConnectionId {
            guest_port: VsockPort(PORT),
            host_port: VsockPort(FIRST_HOST_PORT),
        };
        bridge
            .lock()
            .connections
            .insert(id, Connection::Live(Live::new(stream.into(), true)));
        // As for a shutdown both ways, then the socket's close.
        bridge.close(id);
        bridge.close(id);
        assert!(matches!(
            bridge.lock().connections.get(&id),
            Some(Connection::Closed { from_host: true })
        ));
        assert_eq!(bridge.lock().host_connections(), 1);
        bridge.forget(id);
        assert_eq!(bridge.lock().host_connections(), 0);
    }

    #[test]
    fn stopping_ends_every_socket_and_removes_the_path() {
        let mut f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (mut accepted_stream, _) = f.handshake(PORT);
        let (accepted, _) = f.accept(listener);
        let host = UnixListener::bind(f.port_path(7000)).unwrap();
        let (connected, _) = f.connect(7000);
        let (mut connected_stream, _) = host.accept().unwrap();
        connected_stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut waiting = f.client();
        let unconnected = f.socket();
        f.vsock = None;
        assert!(!f.path.exists());
        assert_closed(&mut waiting);
        assert_eq!(read_to_end(&mut accepted_stream), b"");
        assert_eq!(read_to_end(&mut connected_stream), b"");
        // Their end is published, and stays.
        for socket in [accepted, connected] {
            f.wait(socket, READ | HANGUP);
            assert_eq!(f.receive(socket, 16), None);
        }
        let address = VsockAddress {
            cid: VsockCid::HOST,
            port: VsockPort(7000),
        };
        assert_eq!(
            core_vsock::connect(&f.guest, unconnected, address).unwrap(),
            SocketOutcome::Failed(SocketError::ConnectionReset)
        );
        assert_eq!(
            UnixStream::connect(&f.path).unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }

    /// One byte to send, whose copy, with the provider's lock held, meets
    /// `copying` and waits for `release`.
    struct BlockingBuffer<'a> {
        copying: &'a Barrier,
        release: &'a Barrier,
    }

    impl Buffer for BlockingBuffer<'_> {
        fn len(&self) -> usize {
            1
        }
    }

    impl WriteBuffer for BlockingBuffer<'_> {
        fn copy_to_slice_at(&self, _offset: usize, destination: &mut [u8]) -> Result<(), Fault> {
            self.copying.wait();
            self.release.wait();
            destination.fill(b'x');
            Ok(())
        }

        fn copy_to_raw_at(&self, offset: usize, destination: RawBytes<'_>) -> Result<(), Fault> {
            let mut staged = vec![0; destination.len()];
            self.copy_to_slice_at(offset, &mut staged)?;
            destination.copy_from_slice(&staged);
            Ok(())
        }
    }

    #[test]
    fn stopping_waits_for_guest_operations_in_flight() {
        let mut f = Fixture::new();
        let listener = f.listen(PORT, 4);
        let (mut busy_stream, _) = f.handshake(PORT);
        let (busy, _) = f.accept(listener);
        let (mut other_stream, _) = f.handshake(PORT);
        let (other, _) = f.accept(listener);
        let vsock = f.vsock.take().unwrap();
        let (copying, release) = (Barrier::new(2), Barrier::new(2));
        let f = &f;
        thread::scope(|scope| {
            // Holds the provider's lock until released.
            let sender = scope.spawn(|| {
                core_vsock::send(
                    &f.guest,
                    busy,
                    &BlockingBuffer {
                        copying: &copying,
                        release: &release,
                    },
                    GuestSendFlags::NONE,
                )
            });
            copying.wait();
            let stopper = scope.spawn(move || drop(vsock));
            // Nothing panics until the sender is released, which the scope
            // would wait for; the streams end, and the last poll waits.
            let ended = [&mut busy_stream, &mut other_stream].map(|stream| {
                let mut data = Vec::new();
                stream.read_to_end(&mut data).map(|_| data).ok()
            });
            thread::sleep(Duration::from_millis(100));
            let waited = !stopper.is_finished();
            release.wait();
            let sent = sender.join().unwrap();
            stopper.join().unwrap();
            assert_eq!(ended, [Some(Vec::new()), Some(Vec::new())]);
            assert!(waited, "the drop gave up on its last poll");
            // The stop closed its stream.
            assert_eq!(sent.unwrap(), SocketOutcome::Failed(SocketError::Shutdown));
        });
        assert!(!f.path.exists());
        // The other socket's end is published.
        f.wait(other, READ | HANGUP);
        assert_eq!(f.receive(other, 16), None);
    }

    #[test]
    fn connect_lines_parse_decimal_ports_only() {
        assert_eq!(parse_connect(b"CONNECT 0"), Some(VsockPort(0)));
        assert_eq!(
            parse_connect(b"CONNECT 4294967295"),
            Some(VsockPort(u32::MAX))
        );
        assert_eq!(parse_connect(b"CONNECT 0001024"), Some(VsockPort(1024)));
        for line in [
            &b"CONNECT"[..],
            b"CONNECT ",
            b"CONNECT 4294967296",
            b"CONNECT  1024",
            b"CONNECT 1024\r",
            b"CONNECT +1024",
            b"connect 1",
        ] {
            assert_eq!(parse_connect(line), None);
        }
    }
}
