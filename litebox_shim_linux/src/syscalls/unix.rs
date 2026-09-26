// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix domain socket implementation for the Linux shim layer.

use core::{
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
    time::Duration,
};

use alloc::{
    boxed::Box,
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
    fs::{AccessCredentials, Mode, OFlags, errors::OpenError},
    sync::{Mutex, RwLock},
    utils::TruncateExt as _,
};
use litebox_common_linux::{
    ReceiveFlags, SendFlags, ShutdownHow, SockFlags, SockType, SocketOption, SocketOptionName,
    Ucred, errno::Errno,
};

use crate::{
    FileFd, GlobalState, ShimFS, ShimPlatform, Task, UserPtr, UserPtrMut,
    channel::{Channel, ReadEnd, WriteEnd},
    syscalls::{
        file::TransferredFd,
        net::{SocketOptionValue, SocketOptions},
    },
};

pub(crate) struct UnixSocketSubsystem<Platform: ShimPlatform, FS: ShimFS>(
    core::marker::PhantomData<(Platform, FS)>,
);
impl<Platform: ShimPlatform, FS: ShimFS> FdEnabledSubsystem for UnixSocketSubsystem<Platform, FS> {
    type Entry = UnixSocket<Platform, FS>;
}

impl<Platform: ShimPlatform, FS: ShimFS> FdEnabledSubsystemEntry for UnixSocket<Platform, FS> {}

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
#[derive(PartialEq, Eq, Hash, Debug, Ord, PartialOrd, Clone)]
pub(crate) enum UnixSocketAddrKey {
    // TODO: add inode reference once the file system supports it.
    Path(String),
    Abstract(Vec<u8>),
}

/// Marker used purely for `Arc::ptr_eq` identity of a placeholder reserved
/// in the shared Unix address table. Carries no data of its own.
struct ReservationToken;

/// Next candidate abstract name handed out by autobind, masked to the same
/// 20-bit range Linux draws `sun_path[1..]` from. The mask alone can't give
/// collision-freedom (it wraps every 2^20 binds), so the picking loop in
/// `UnixSocketAddr::bind_and_reserve` retries through `reserve_unix_addr`
/// against the live table on every draw.
static AUTOBIND_COUNTER: AtomicU32 = AtomicU32::new(0);

/// The `SO_PEERCRED` view of a task: its process id and *effective* ids, as
/// Linux's `cred_to_ucred` reports them.
fn task_ucred<Platform: ShimPlatform, FS: ShimFS>(task: &Task<Platform, FS>) -> Ucred {
    let credentials = task.credentials.borrow();
    Ucred {
        pid: task.pid.cast_unsigned(),
        uid: credentials.euid,
        gid: credentials.egid,
    }
}

/// The `SCM_CREDENTIALS` a task implicitly attaches to what it sends: its
/// process id and *real* ids, as Linux's `maybe_add_creds` captures them
/// (`task_tgid(current)` + `current_uid_gid`).
fn task_send_ucred<Platform: ShimPlatform, FS: ShimFS>(task: &Task<Platform, FS>) -> Ucred {
    let credentials = task.credentials.borrow();
    Ucred {
        pid: task.pid.cast_unsigned(),
        uid: credentials.uid,
        gid: credentials.gid,
    }
}

/// What a `SO_PASSCRED` receiver sees when no sender credentials are
/// attached to what it read (EOF, for instance): pid 0 and the overflow
/// ids, matching Linux's `from_kuid_munged(INVALID_UID)`.
const UNSET_UCRED: Ucred = Ucred {
    pid: 0,
    uid: 65534,
    gid: 65534,
};

/// An exclusive claim on one key in the shared Unix address table, held
/// from `bind()` time until the socket either upgrades it into a real
/// listening/datagram entry (`upgrade`) or is dropped without ever doing
/// so, at which point `Drop` releases the placeholder.
///
/// This is what makes address-collision detection atomic and total: every
/// real bind path (autobind, explicit path, explicit abstract) claims
/// through the same `reserve_unix_addr`, under one write-lock critical
/// section covering both the check and the insert, so a bound-but-not-yet-
/// listening socket is exactly as visible to a colliding bind as a fully
/// listening one -- and two concurrent binds to the same address can never
/// both observe it as free.
struct UnixAddrReservation<Platform: ShimPlatform, FS: ShimFS> {
    key: UnixSocketAddrKey,
    token: Arc<ReservationToken>,
    global: Arc<GlobalState<Platform, FS>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> UnixAddrReservation<Platform, FS> {
    /// Atomically replaces this reservation's placeholder in the shared
    /// table with the finished entry, consuming the reservation. Nothing
    /// else can observe or touch a `Reserved` slot except through this same
    /// token (see `reserve_unix_addr` and this type's `Drop`), so the slot
    /// is guaranteed to still hold our own placeholder here.
    fn upgrade(self, entry: UnixEntryInner<Platform, FS>) {
        let mut table = self.global.unix_addr_table.write();
        if let Some(slot) = table.get_mut(&self.key) {
            debug_assert!(
                matches!(&slot.0, UnixEntryInner::Reserved(current) if Arc::ptr_eq(current, &self.token)),
                "unix_addr_table slot changed out from under an unconsumed reservation"
            );
            slot.0 = entry;
        } else {
            debug_assert!(false, "unix_addr_table reservation missing at upgrade time");
        }
        // `table`'s write lock is released here, before `self` (and its own
        // `Drop`) runs at the end of this function -- that `Drop` will find
        // the slot no longer `Reserved` and no-op.
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for UnixAddrReservation<Platform, FS> {
    fn drop(&mut self) {
        let mut table = self.global.unix_addr_table.write();
        if let Some(UnixEntry(UnixEntryInner::Reserved(current))) = table.get(&self.key)
            && Arc::ptr_eq(current, &self.token)
        {
            table.remove(&self.key);
        }
    }
}

/// A bound address together with its (optional) shared-table reservation.
/// `None` for path addresses -- see `UnixSocketAddr::bind_and_reserve`.
type BoundUnixAddr<Platform, FS> = (
    UnixBoundSocketAddr<FS>,
    Option<UnixAddrReservation<Platform, FS>>,
);

/// Atomically checks and claims `key` in the shared Unix address table: a
/// single write-lock acquisition covers both the presence check and the
/// insert, so no other bind can observe the key as free in between (the
/// check-then-act race a read-then-separate-write split would allow).
/// Released quickly -- callers must not hold this call's result across
/// unrelated I/O (e.g. filesystem access) any longer than necessary, so
/// unrelated binds to other keys are never blocked behind it.
fn reserve_unix_addr<Platform: ShimPlatform, FS: ShimFS>(
    global: &Arc<GlobalState<Platform, FS>>,
    key: UnixSocketAddrKey,
) -> Result<UnixAddrReservation<Platform, FS>, Errno> {
    let mut table = global.unix_addr_table.write();
    if table.contains_key(&key) {
        return Err(Errno::EADDRINUSE);
    }
    let token = Arc::new(ReservationToken);
    table.insert(
        key.clone(),
        UnixEntry(UnixEntryInner::Reserved(token.clone())),
    );
    drop(table);
    Ok(UnixAddrReservation {
        key,
        token,
        global: global.clone(),
    })
}

/// Mode bits used when creating (or merely reopening) a Unix socket path
/// file. Mirrors the permissions Linux itself grants a freshly bound socket
/// inode.
fn unix_socket_file_mode() -> Mode {
    Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH
}

impl UnixSocketAddr {
    /// Returns true if this is an unnamed socket address.
    fn is_unnamed(&self) -> bool {
        matches!(self, UnixSocketAddr::Unnamed)
    }

    /// Validates that `self` is reachable as a `connect()` target, mirroring
    /// Linux's own permission/existence check on the peer's path. Performs
    /// no reservation and never touches the shared address table -- the
    /// peer's own `bind` already owns whatever entry exists there, and this
    /// is only a read-only check on our end.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be reached (e.g., file
    /// doesn't exist, permission denied).
    fn check_reachable<Platform: ShimPlatform, FS: ShimFS>(
        self,
        task: &Task<Platform, FS>,
    ) -> Result<UnixBoundSocketAddr<FS>, Errno> {
        match self {
            UnixSocketAddr::Path(path) => {
                // TODO: extend fs to support creating sock file (i.e., with type `InodeType::Socket`)
                let credential_snapshot = task.credentials.borrow().clone();
                let credentials = AccessCredentials::new(
                    credential_snapshot.euid,
                    credential_snapshot.egid,
                    credential_snapshot.supplementary_groups(),
                );
                let fs = task.files.borrow().fs.clone();
                let file = fs
                    .open_as(
                        credentials,
                        path.as_str(),
                        OFlags::RDWR,
                        unix_socket_file_mode(),
                    )
                    .map_err(|err| match err {
                        OpenError::AlreadyExists => Errno::EADDRINUSE,
                        other => Errno::from(other),
                    })?;
                Ok(UnixBoundSocketAddr::Path((path, file, fs)))
            }
            UnixSocketAddr::Abstract(data) => Ok(UnixBoundSocketAddr::Abstract(data)),
            // Nothing legitimately connects to an unnamed address.
            UnixSocketAddr::Unnamed => Err(Errno::EINVAL),
        }
    }

    /// Claims `self` exclusively. This is the real `bind(2)` path, shared by
    /// stream `bind` and datagram `bind` -- every real bind goes through
    /// this single function, so every real bind is subject to the same
    /// collision check.
    ///
    /// For abstract (and autobound) addresses, which have no filesystem
    /// backing, the returned `Some(reservation)` atomically reserves the
    /// address in the shared table (see `reserve_unix_addr`); the caller
    /// must upgrade it into a real entry (`UnixAddrReservation::upgrade`)
    /// once the bind is otherwise complete.
    ///
    /// For path addresses the return is `None`: collision detection for
    /// paths is the filesystem's own `O_EXCL` create, keyed on the path
    /// *string* resolving to an inode, not on any copy of that string held
    /// elsewhere -- the same reason two listening sockets can legitimately
    /// share one path string over time (bind, unlink, bind again) while the
    /// first is still alive, elsewhere. The shared table has no inode
    /// identity to key on yet (see `UnixSocketAddrKey`'s own `TODO`), so
    /// routing it through `reserve_unix_addr` would reject that legitimate
    /// unlink-and-rebind sequence just because the *string* is still
    /// present from the first, now-unreachable-by-path bind. The caller
    /// inserts unconditionally for this case, exactly as it did before this
    /// reservation scheme existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is already in use, or (for path
    /// addresses) cannot be created.
    fn bind_and_reserve<Platform: ShimPlatform, FS: ShimFS>(
        self,
        task: &Task<Platform, FS>,
    ) -> Result<BoundUnixAddr<Platform, FS>, Errno> {
        match self {
            UnixSocketAddr::Path(path) => {
                // TODO: extend fs to support creating sock file (i.e., with type `InodeType::Socket`)
                let credential_snapshot = task.credentials.borrow().clone();
                let credentials = AccessCredentials::new(
                    credential_snapshot.euid,
                    credential_snapshot.egid,
                    credential_snapshot.supplementary_groups(),
                );
                let fs = task.files.borrow().fs.clone();
                let file = fs
                    .open_as(
                        credentials,
                        path.as_str(),
                        OFlags::CREAT | OFlags::EXCL | OFlags::RDWR,
                        unix_socket_file_mode(),
                    )
                    .map_err(|err| match err {
                        OpenError::AlreadyExists => Errno::EADDRINUSE,
                        other => Errno::from(other),
                    })?;
                Ok((UnixBoundSocketAddr::Path((path, file, fs)), None))
            }
            UnixSocketAddr::Abstract(data) => {
                let reservation =
                    reserve_unix_addr(&task.global, UnixSocketAddrKey::Abstract(data.clone()))?;
                Ok((UnixBoundSocketAddr::Abstract(data), Some(reservation)))
            }
            UnixSocketAddr::Unnamed => {
                // Autobind: draw a fresh candidate from Linux's 20-bit
                // abstract namespace and atomically reserve it, retrying
                // past a collision. Each candidate's check-and-reserve is
                // its own short critical section (see `reserve_unix_addr`)
                // -- the retry loop deliberately never holds the table lock
                // across attempts, so unrelated binds are never blocked
                // behind an autobind search.
                for _ in 0..=0xFFFFFu32 {
                    let name = AUTOBIND_COUNTER.fetch_add(1, Ordering::Relaxed) & 0xFFFFF;
                    let candidate = alloc::format!("{name:05x}").into_bytes();
                    match reserve_unix_addr(
                        &task.global,
                        UnixSocketAddrKey::Abstract(candidate.clone()),
                    ) {
                        Ok(reservation) => {
                            return Ok((
                                UnixBoundSocketAddr::Abstract(candidate),
                                Some(reservation),
                            ));
                        }
                        // Try the next candidate.
                        Err(Errno::EADDRINUSE) => {}
                        Err(other) => return Err(other),
                    }
                }
                Err(Errno::ENOSPC)
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

/// A rejected `UnixInitStream`, handed back to the caller alongside the
/// `Errno` that rejected it (so the caller can keep using the socket, e.g.
/// on a failed `listen()` or `connect()`). Boxed because `UnixInitStream`
/// carries its own `BoundUnixAddr`, which makes the pair large enough that
/// `Result`'s error variant would otherwise dominate the type's size.
type InitRejection<Platform, FS> = Box<(UnixInitStream<Platform, FS>, Errno)>;

/// Represents a Unix stream socket in its initial state.
///
/// This is the state immediately after socket creation, before the socket
/// has been connected, or put into listening mode.
struct UnixInitStream<Platform: ShimPlatform, FS: ShimFS> {
    /// The bound address and its table reservation (if any -- path
    /// addresses have none, see `UnixSocketAddr::bind_and_reserve`), set
    /// together by `bind` and released together -- kept as one field
    /// (rather than two separate top-level `Option`s) so the two can never
    /// go out of sync with each other.
    bound: Option<BoundUnixAddr<Platform, FS>>,
    pollee: Pollee<Platform>,
    read_shutdown: AtomicBool,
    write_shutdown: AtomicBool,
}

impl<Platform: ShimPlatform, FS: ShimFS> UnixInitStream<Platform, FS> {
    fn new() -> Self {
        Self {
            bound: None,
            pollee: Pollee::new(),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
        }
    }

    fn shutdown(&self, how: ShutdownHow) {
        if how.is_shutdown_read() && !self.read_shutdown.swap(true, Ordering::Release) {
            self.pollee.notify_observers(Events::IN);
        }
        if how.is_shutdown_write() {
            self.write_shutdown.store(true, Ordering::Release);
        }
    }

    /// Binds this socket to the given address.
    fn bind(&mut self, task: &Task<Platform, FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        if self.bound.is_some() && !addr.is_unnamed() {
            return Err(Errno::EINVAL);
        }
        if self.bound.is_none() {
            self.bound = Some(addr.bind_and_reserve(task)?);
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
        global: &Arc<GlobalState<Platform, FS>>,
        listener_cred: Ucred,
    ) -> Result<UnixListenStream<Platform, FS>, InitRejection<Platform, FS>> {
        let Some((addr, reservation)) = self.bound else {
            return Err(Box::new((self, Errno::EINVAL)));
        };
        let key = addr.to_key();
        let backlog = Arc::new(Backlog::new(addr, backlog, self.pollee, listener_cred));
        if let Some(reservation) = reservation {
            // Upgrade the existing reservation in place instead of
            // inserting a fresh table entry -- the slot has been ours,
            // exclusively, since `bind` reserved it.
            reservation.upgrade(UnixEntryInner::Stream(backlog.clone()));
        } else {
            // Path addresses were never reserved through the table at bind
            // time (see `bind_and_reserve`) -- insert unconditionally,
            // exactly as this did before the reservation scheme existed.
            global
                .unix_addr_table
                .write()
                .insert(key, UnixEntry(UnixEntryInner::Stream(backlog.clone())));
        }
        Ok(UnixListenStream {
            backlog,
            global: global.clone(),
        })
    }

    /// Converts this initial socket into a connected stream pair.
    fn into_connected(
        self,
        self_cred: Ucred,
        peer_addr: Arc<UnixBoundSocketAddr<FS>>,
        peer_cred: Ucred,
    ) -> (
        UnixConnectedStream<Platform, FS>,
        UnixConnectedStream<Platform, FS>,
    ) {
        let UnixInitStream {
            bound,
            pollee,
            read_shutdown,
            write_shutdown,
        } = self;
        let (addr, reservation) = match bound {
            Some((addr, reservation)) => (Some(Arc::new(addr)), reservation),
            None => (None, None),
        };
        // The reservation (if this socket explicitly bound before
        // connecting -- the client-role autobind-then-connect pattern)
        // carries into the connected stream rather than being dropped here,
        // so the bound address stays claimed for the connection's whole
        // lifetime, matching real Unix domain socket semantics.
        UnixConnectedStream::new_pair(
            addr,
            self_cred,
            Some(Arc::new(pollee)),
            Some(peer_addr),
            peer_cred,
            reservation,
            read_shutdown.load(Ordering::Acquire),
            write_shutdown.load(Ordering::Acquire),
            false,
        )
    }
}

/// Connection backlog for a listening Unix socket.
///
/// Manages the queue of pending connections and the maximum backlog limit.
struct Backlog<Platform: ShimPlatform, FS: ShimFS> {
    /// The address this socket is listening on
    addr: Arc<UnixBoundSocketAddr<FS>>,
    listener_cred: Ucred,
    state: Mutex<Platform, BacklogState<Platform, FS>>,
    pollee: Pollee<Platform>,
}

struct BacklogState<Platform: ShimPlatform, FS: ShimFS> {
    sockets: VecDeque<UnixConnectedStream<Platform, FS>>,
    /// Maximum number of pending connections
    limit: u16,
    is_shutdown: bool,
}

impl<Platform: ShimPlatform, FS: ShimFS> Backlog<Platform, FS> {
    fn new(
        addr: UnixBoundSocketAddr<FS>,
        backlog: u16,
        pollee: Pollee<Platform>,
        listener_cred: Ucred,
    ) -> Self {
        Self {
            addr: Arc::new(addr),
            listener_cred,
            state: litebox::sync::Mutex::new(BacklogState {
                sockets: VecDeque::new(),
                limit: backlog,
                is_shutdown: false,
            }),
            pollee,
        }
    }

    /// Updates the maximum backlog size.
    fn set_backlog(&self, backlog: u16) {
        self.state.lock().limit = backlog;
    }

    /// Attempts to establish a connection without blocking.
    fn try_connect(
        &self,
        init: UnixInitStream<Platform, FS>,
        client_cred: Ucred,
    ) -> Result<UnixConnectedStream<Platform, FS>, InitRejection<Platform, FS>> {
        let mut state = self.state.lock();
        if state.is_shutdown {
            return Err(Box::new((init, Errno::ECONNREFUSED)));
        }

        if state.sockets.len() >= state.limit as usize {
            return Err(Box::new((init, Errno::EAGAIN)));
        }

        let (client, server) =
            init.into_connected(client_cred, self.addr.clone(), self.listener_cred);
        state.sockets.push_back(server);

        self.pollee.notify_observers(Events::IN);
        Ok(client)
    }

    /// Attempts to accept a pending connection without blocking.
    fn try_accept(&self) -> Result<UnixConnectedStream<Platform, FS>, TryOpError<Errno>> {
        let mut state = self.state.lock();
        match state.sockets.pop_front() {
            Some(stream) => {
                if !state.is_shutdown {
                    self.pollee.notify_observers(Events::OUT);
                }
                Ok(stream)
            }
            None if state.is_shutdown => Err(TryOpError::Other(Errno::ESHUTDOWN)),
            None => Err(TryOpError::TryAgain),
        }
    }

    fn check_io_events(&self) -> Events {
        let state = self.state.lock();
        let mut events = Events::empty();
        if !state.sockets.is_empty() {
            events |= Events::IN;
        }
        if state.is_shutdown {
            events |= Events::IN | Events::HUP;
        } else if state.sockets.len() < state.limit as usize {
            events |= Events::OUT;
        }
        events
    }

    /// Shuts down this backlog, preventing new connections.
    fn shutdown(&self) {
        let mut state = self.state.lock();
        if !state.is_shutdown {
            state.is_shutdown = true;
            self.pollee.notify_observers(Events::HUP);
        }
    }
}

/// Represents a Unix stream socket in listening state.
struct UnixListenStream<Platform: ShimPlatform, FS: ShimFS> {
    backlog: Arc<Backlog<Platform, FS>>,
    global: Arc<GlobalState<Platform, FS>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> UnixListenStream<Platform, FS> {
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
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for UnixListenStream<Platform, FS> {
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

/// A message sent over a Unix socket.
struct Message<Platform: ShimPlatform, FS: ShimFS> {
    data: Vec<u8>,
    rights: Vec<TransferredFd<Platform, FS>>,
    /// The sender's credentials, captured when the message was queued
    /// (explicit `SCM_CREDENTIALS` if the sender supplied one, else its
    /// process id and real ids).
    credentials: Ucred,
}

pub(super) struct RecvResult<Platform: ShimPlatform, FS: ShimFS> {
    pub(super) size: usize,
    pub(super) rights: Vec<TransferredFd<Platform, FS>>,
    /// `Some` only when the receiving socket has `SO_PASSCRED` set: the
    /// `SCM_CREDENTIALS` payload to deliver (the first consumed message's
    /// sender credentials).
    pub(super) credentials: Option<Ucred>,
}

/// Represents a connected Unix stream socket.
struct UnixConnectedStream<Platform: ShimPlatform, FS: ShimFS> {
    addr: AddrView<FS>,
    peer_cred: Ucred,
    /// The read end of the local socket's channel for receiving messages.
    recv_channel: crate::channel::ReadEnd<Platform, Message<Platform, FS>>,
    /// The write end of the connected peer socket for sending messages.
    connected_send_channel: crate::channel::WriteEnd<Platform, Message<Platform, FS>>,
    pollee: Arc<Pollee<Platform>>,
    preserve_message_boundaries: bool,
    /// Kept alive only for its `Drop` side effect: releases this stream's
    /// own bound-address reservation (if it explicitly bound before
    /// connecting) once the connection itself closes, not merely once it
    /// stops listening -- matching real Unix domain socket semantics, where
    /// a bound client address stays claimed for as long as the socket
    /// exists.
    _reservation: Option<UnixAddrReservation<Platform, FS>>,
}

const UNIX_BUF_SIZE: usize = 65536;
impl<Platform: ShimPlatform, FS: ShimFS> UnixConnectedStream<Platform, FS> {
    /// Creates a pair of connected Unix stream sockets.
    ///
    /// `read_shutdown` and `write_shutdown` half-close the corresponding sides of the
    /// *first* returned socket only (used to carry pre-connect shutdown flags from
    /// `UnixInitStream` across `connect(2)` into the connected state). `reservation`
    /// (if any) belongs to the *first* returned socket only, matching `addr`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the arguments initialize distinct state for both socket endpoints"
    )]
    fn new_pair(
        addr: Option<Arc<UnixBoundSocketAddr<FS>>>,
        self_cred: Ucred,
        pollee: Option<Arc<Pollee<Platform>>>,
        peer: Option<Arc<UnixBoundSocketAddr<FS>>>,
        peer_cred: Ucred,
        reservation: Option<UnixAddrReservation<Platform, FS>>,
        read_shutdown: bool,
        write_shutdown: bool,
        preserve_message_boundaries: bool,
    ) -> (Self, Self) {
        let (addr1, addr2) = AddrView::new_pair(addr, peer);
        let pollee1 = pollee.unwrap_or(Arc::new(Pollee::new()));
        let pollee2 = Arc::new(Pollee::new());
        let (send_channel, recv_channel) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee2.clone(), pollee1.clone()).split();
        let (send_channel_peer, recv_channel_peer) =
            crate::channel::Channel::new(UNIX_BUF_SIZE, pollee1.clone(), pollee2.clone()).split();
        let first = UnixConnectedStream {
            addr: addr1,
            peer_cred,
            recv_channel,
            connected_send_channel: send_channel_peer,
            pollee: pollee1,
            preserve_message_boundaries,
            _reservation: reservation,
        };
        let second = UnixConnectedStream {
            addr: addr2,
            peer_cred: self_cred,
            recv_channel: recv_channel_peer,
            connected_send_channel: send_channel,
            pollee: pollee2,
            preserve_message_boundaries,
            _reservation: None,
        };
        if read_shutdown {
            first.recv_channel.shutdown();
        }
        if write_shutdown {
            first.connected_send_channel.shutdown();
        }
        (first, second)
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

    fn try_sendto(&self, msg: Message<Platform, FS>) -> Result<(), (Message<Platform, FS>, Errno)> {
        // TODO: write partial data?
        self.connected_send_channel.try_write_one(msg)
    }

    /// `want_credentials` is the receiving socket's `SO_PASSCRED`: when set, the
    /// result carries the first consumed message's sender credentials and a
    /// stream read stops at a message whose sender credentials differ from
    /// them, as Linux's `unix_stream_read_generic` does (`unix_skb_scm_eq`),
    /// so one `SCM_CREDENTIALS` always describes every byte returned.
    fn try_recvfrom(
        &self,
        mut buf: &mut [u8],
        want_credentials: bool,
    ) -> Result<RecvResult<Platform, FS>, TryOpError<Errno>> {
        if buf.is_empty() {
            return Ok(RecvResult {
                size: 0,
                rights: Vec::new(),
                credentials: want_credentials.then_some(UNSET_UCRED),
            });
        }
        if self.preserve_message_boundaries {
            return self
                .recv_channel
                .peek_and_consume_one(|msg| {
                    let message_len = msg.data.len();
                    let copy_len = buf.len().min(message_len);
                    buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                    Ok((
                        true,
                        RecvResult {
                            size: message_len,
                            rights: core::mem::take(&mut msg.rights),
                            credentials: want_credentials.then_some(msg.credentials),
                        },
                    ))
                })
                .map_err(|e| match e {
                    Errno::EAGAIN => TryOpError::TryAgain,
                    other => TryOpError::Other(other),
                });
        }

        let mut result = RecvResult {
            size: 0,
            rights: Vec::new(),
            credentials: None,
        };
        while !buf.is_empty() {
            let (n, mut rights, credentials, ancillary_barrier) =
                match self.recv_channel.peek_and_consume_one(|msg| {
                    if want_credentials
                        && let Some(first) = result.credentials
                        && first != msg.credentials
                    {
                        // Credentials boundary: leave this message queued for
                        // the next read.
                        return Err(Errno::EAGAIN);
                    }
                    let ancillary_barrier = !msg.rights.is_empty();
                    let copy_len = buf.len().min(msg.data.len());
                    buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                    let rights = if copy_len == 0 {
                        Vec::new()
                    } else {
                        core::mem::take(&mut msg.rights)
                    };
                    let credentials = msg.credentials;
                    if copy_len == msg.data.len() {
                        Ok((true, (copy_len, rights, credentials, ancillary_barrier)))
                    } else {
                        msg.data = msg.data.split_off(copy_len);
                        Ok((false, (copy_len, rights, credentials, ancillary_barrier)))
                    }
                }) {
                    Ok(value) => value,
                    Err(e) => {
                        if result.size > 0 {
                            break;
                        }
                        return match e {
                            Errno::EAGAIN => Err(TryOpError::TryAgain),
                            other => Err(TryOpError::Other(other)),
                        };
                    }
                };
            result.size += n;
            result.rights.append(&mut rights);
            if want_credentials && result.credentials.is_none() {
                result.credentials = Some(credentials);
            }
            buf = &mut buf[n..];
            if ancillary_barrier {
                break;
            }
        }
        Ok(result)
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::empty();
        let is_read_shutdown = self.recv_channel.is_shutdown();
        let is_peer_write_shutdown = self.recv_channel.is_peer_shutdown();
        let is_write_shutdown = self.connected_send_channel.is_shutdown();
        if is_read_shutdown || is_peer_write_shutdown {
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

    fn shutdown(&self, how: ShutdownHow) {
        let mut events = Events::empty();
        if how.is_shutdown_read() && self.recv_channel.shutdown() {
            events |= Events::IN | Events::RDHUP;
        }
        if how.is_shutdown_write() && self.connected_send_channel.shutdown() {
            events |= Events::OUT | Events::HUP;
        }
        self.pollee.notify_observers(events);
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for UnixConnectedStream<Platform, FS> {
    fn drop(&mut self) {
        self.recv_channel.shutdown();
        self.connected_send_channel.shutdown();
    }
}

enum UnixStreamState<Platform: ShimPlatform, FS: ShimFS> {
    Init(UnixInitStream<Platform, FS>),
    Listen(UnixListenStream<Platform, FS>),
    Connected(UnixConnectedStream<Platform, FS>),
}

impl<Platform: ShimPlatform, FS: ShimFS> UnixStreamState<Platform, FS> {
    fn connected(&self) -> Option<&UnixConnectedStream<Platform, FS>> {
        match self {
            UnixStreamState::Connected(conn) => Some(conn),
            _ => None,
        }
    }
    fn listen(&self) -> Option<&UnixListenStream<Platform, FS>> {
        match self {
            UnixStreamState::Listen(listen) => Some(listen),
            _ => None,
        }
    }
}

struct UnixStream<Platform: ShimPlatform, FS: ShimFS> {
    state: RwLock<Platform, Option<UnixStreamState<Platform, FS>>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> UnixStream<Platform, FS> {
    fn new(state: UnixStreamState<Platform, FS>) -> Self {
        Self {
            state: litebox::sync::RwLock::new(Some(state)),
        }
    }

    fn with_state_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&UnixStreamState<Platform, FS>) -> R,
    {
        let old = self.state.read();
        f(old.as_ref().expect("state should never be None"))
    }

    fn with_state_mut_ref<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut UnixStreamState<Platform, FS>) -> R,
    {
        let mut old = self.state.write();
        f(old.as_mut().expect("state should never be None"))
    }

    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(UnixStreamState<Platform, FS>) -> (UnixStreamState<Platform, FS>, R),
    {
        let mut old = self.state.write();
        let (new, result) = f(old.take().expect("state should never be None"));
        *old = Some(new);
        result
    }

    fn bind(&self, task: &Task<Platform, FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
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
        backlog: u16,
        global: &Arc<GlobalState<Platform, FS>>,
        listener_cred: Ucred,
    ) -> Result<(), Errno> {
        self.with_state(|state| {
            let ret = match state {
                UnixStreamState::Init(init) => {
                    return match init.listen(backlog, global, listener_cred) {
                        Ok(listen) => (UnixStreamState::Listen(listen), Ok(())),
                        Err(boxed) => {
                            let (init, err) = *boxed;
                            (UnixStreamState::Init(init), Err(err))
                        }
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

    fn lookup(
        &self,
        task: &Task<Platform, FS>,
        addr: &UnixSocketAddr,
    ) -> Result<Arc<Backlog<Platform, FS>>, Errno> {
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
            // Bound but not (yet) listening: nothing is there to connect to,
            // exactly like Linux's ECONNREFUSED for a non-listening peer.
            UnixEntryInner::Reserved(_) => Err(Errno::ECONNREFUSED),
        }
    }
    fn try_connect(
        &self,
        backlog: &Backlog<Platform, FS>,
        client_cred: Ucred,
    ) -> Result<(), TryOpError<Errno>> {
        self.with_state(|state| match state {
            UnixStreamState::Init(init) => match backlog.try_connect(init, client_cred) {
                Ok(connected) => (UnixStreamState::Connected(connected), Ok(())),
                Err(boxed) => {
                    let (init, err) = *boxed;
                    (UnixStreamState::Init(init), Err(err))
                }
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
        task: &Task<Platform, FS>,
        addr: UnixSocketAddr,
        is_nonblocking: bool,
    ) -> Result<(), Errno> {
        let backlog = self.lookup(task, &addr)?;
        // check if we can reach the address
        let _ = addr.check_reachable(task)?;
        let client_cred = task_ucred(task);
        task.wait_cx()
            .wait_on_events(
                is_nonblocking,
                Events::OUT,
                |observer, mask| {
                    backlog.pollee.register_observer(observer, mask);
                    Ok(())
                },
                || self.try_connect(&backlog, client_cred),
            )
            .map_err(Errno::from)
    }

    fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        mut peer: Option<&mut UnixSocketAddr>,
        is_nonblocking: bool,
    ) -> Result<UnixSocketInner<Platform, FS>, Errno> {
        let backlog =
            self.with_state_ref(|state| -> Result<Arc<Backlog<Platform, FS>>, Errno> {
                let listen = state.listen().ok_or(Errno::EINVAL)?;
                Ok(listen.backlog.clone())
            })?;
        let res = cx
            .wait_on_events(
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
            .map_err(Errno::from);
        // accept on a shut-down listen: Linux returns EAGAIN for non-blocking, EINVAL
        // for blocking. try_accept signals shutdown via ESHUTDOWN; translate here.
        match res {
            Err(Errno::ESHUTDOWN) if is_nonblocking => Err(Errno::EAGAIN),
            Err(Errno::ESHUTDOWN) => Err(Errno::EINVAL),
            other => other,
        }
    }

    fn sendto(
        &self,
        cx: &WaitContext<'_, Platform>,
        timeout: Option<Duration>,
        msg: Message<Platform, FS>,
        is_nonblocking: bool,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let len = msg.data.len();
        if len == 0 {
            return Ok(0);
        }
        let mut msg = Some(msg);
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
                            Ok(()) => Ok(len),
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
        cx: &WaitContext<'_, Platform>,
        timeout: Option<Duration>,
        buf: &mut [u8],
        is_nonblocking: bool,
        want_credentials: bool,
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<RecvResult<Platform, FS>, Errno> {
        let res = cx
            .with_timeout(timeout)
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
                        let n = conn.try_recvfrom(buf, want_credentials)?;
                        // For connected stream sockets, no need to return the source address
                        if let Some(source_addr) = source_addr.as_deref_mut() {
                            *source_addr = None;
                        }
                        Ok(n)
                    })
                },
            )
            .map_err(Errno::from);
        match res {
            // Linux SO_RCVTIMEO expiry surfaces as `EAGAIN`, not `ETIMEDOUT`
            Err(Errno::ETIMEDOUT) => Err(Errno::EAGAIN),
            other => other,
        }
    }

    fn get_local_addr(&self) -> UnixSocketAddr {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(init) => init
                .bound
                .as_ref()
                .map_or(UnixSocketAddr::Unnamed, |(addr, _)| {
                    UnixSocketAddr::from(addr)
                }),
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

    fn get_peer_cred(&self) -> Option<Ucred> {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(_) | UnixStreamState::Listen(_) => None,
            UnixStreamState::Connected(connect) => Some(connect.peer_cred),
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

    fn unregister_observer(&self, observer: Weak<dyn litebox::event::observer::Observer<Events>>) {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(init) => init.pollee.unregister_observer(observer),
            UnixStreamState::Listen(listen) => {
                listen.backlog.pollee.unregister_observer(observer);
            }
            UnixStreamState::Connected(connect) => {
                connect.pollee.unregister_observer(observer);
            }
        });
    }

    fn check_io_events(&self) -> Events {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(init) => {
                // Fresh Init reports OUT|HUP (HUP because not connected). After a
                // shutdown(SHUT_RD) on an Init socket, Linux additionally reports IN
                // (a recv would return EOF immediately). SHUT_WR has no observable
                // effect on Init's poll output.
                let mut events = Events::OUT | Events::HUP;
                if init.read_shutdown.load(Ordering::Acquire) {
                    events |= Events::IN;
                }
                events
            }
            UnixStreamState::Listen(listen) => listen.backlog.check_io_events(),
            UnixStreamState::Connected(conn) => conn.check_io_events(),
        })
    }

    fn shutdown(&self, how: ShutdownHow) {
        self.with_state_ref(|state| match state {
            UnixStreamState::Init(init) => init.shutdown(how),
            UnixStreamState::Listen(listen) => {
                if how.is_shutdown_read() {
                    listen.backlog.shutdown();
                }
            }
            UnixStreamState::Connected(conn) => conn.shutdown(how),
        });
    }
}

/// A datagram message with source address information
#[derive(Clone)]
struct DatagramMessage {
    data: Vec<u8>,
    // TODO: add SCM_RIGHTS
    source: UnixSocketAddr,
    /// The sender's credentials, captured when the datagram was queued (see
    /// `Message::credentials`).
    credentials: Ucred,
}

impl<Platform: ShimPlatform> WriteEnd<Platform, DatagramMessage> {
    fn try_write(&self, msg: DatagramMessage) -> Result<(), (DatagramMessage, Errno)> {
        self.try_write_one(msg)
    }
    fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
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
impl<Platform: ShimPlatform> ReadEnd<Platform, DatagramMessage> {
    /// Attempts to read a single datagram message without blocking.
    ///
    /// Reads exactly one message, preserving message boundaries. If the buffer
    /// is smaller than the message, the excess data is discarded (truncated).
    /// Returns the original message size (which may exceed `buf.len()`) and
    /// the sender's credentials.
    fn try_read(
        &self,
        buf: &mut [u8],
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<(usize, Ucred), TryOpError<Errno>> {
        let is_self_shutdown = self.is_shutdown();
        self.peek_and_consume_one(|msg| {
            let copy_len = buf.len().min(msg.data.len());
            buf[..copy_len].copy_from_slice(&msg.data[..copy_len]);
            if let Some(source_addr) = source_addr.as_deref_mut() {
                *source_addr = Some(msg.source.clone());
            }
            // Always consume the entire message to preserve boundaries.
            Ok((true, (msg.data.len(), msg.credentials)))
        })
        .map_err(|e| match e {
            Errno::EAGAIN => TryOpError::TryAgain,
            // ESHUTDOWN from the channel layer collapses two distinct conditions: our own
            // SHUT_RD (caller wants EOF) and peer SHUT_WR (Linux keeps the socket
            // receivable in principle, since other senders could still target it). For
            // datagram, only the self case synthesizes EOF; peer-shutdown looks like
            // "empty queue, try again".
            Errno::ESHUTDOWN if !is_self_shutdown => TryOpError::TryAgain,
            other => TryOpError::Other(other),
        })
    }
}

/// The local address of a bound datagram socket together with the global state
/// it was registered in (used to deregister the address on drop).
type BoundDatagramAddr<Platform, FS> = (UnixBoundSocketAddr<FS>, Arc<GlobalState<Platform, FS>>);

struct UnixDatagramInner<Platform: ShimPlatform, FS: ShimFS> {
    /// The local address this socket is bound to, if any.
    addr: Option<BoundDatagramAddr<Platform, FS>>,
    /// The read end of the local socket's channel for receiving messages.
    /// Set when the socket is bound via `bind` or `new_pair`.
    recv_channel: Option<ReadEnd<Platform, DatagramMessage>>,
    /// The write end of the connected peer socket for sending messages.
    /// Set when the socket is connected via `connect` or `new_pair`.
    connected_send_channel: Option<(WriteEnd<Platform, DatagramMessage>, UnixSocketAddr)>,
    read_shutdown: bool,
    write_shutdown: bool,
    pollee: Arc<Pollee<Platform>>,
}
/// Represents a Unix datagram socket.
struct UnixDatagram<Platform: ShimPlatform, FS: ShimFS> {
    inner: RwLock<Platform, UnixDatagramInner<Platform, FS>>,
}

impl<Platform: ShimPlatform, FS: ShimFS> Drop for UnixDatagramInner<Platform, FS> {
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

impl<Platform: ShimPlatform, FS: ShimFS> UnixDatagramInner<Platform, FS> {
    /// Binds this socket to the given address.
    fn bind(&mut self, task: &Task<Platform, FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        if self.addr.is_some() {
            if addr.is_unnamed() {
                return Ok(());
            }
            return Err(Errno::EINVAL);
        }

        let (bound_addr, reservation) = addr.bind_and_reserve(task)?;
        // Registers the write end of the socket in the global address table so it
        // can receive messages sent to this address.
        let (send_channel, recv_channel) =
            Channel::new(UNIX_BUF_SIZE, Arc::new(Pollee::new()), self.pollee.clone()).split();
        if let Some(reservation) = reservation {
            // Upgrade the reservation `bind_and_reserve` already atomically
            // claimed, rather than inserting a fresh entry that could race
            // a colliding bind.
            reservation.upgrade(UnixEntryInner::Datagram(send_channel));
        } else {
            // Path addresses were never reserved through the table at bind
            // time (see `bind_and_reserve`) -- insert unconditionally,
            // exactly as this did before the reservation scheme existed.
            let key = bound_addr.to_key();
            task.global
                .unix_addr_table
                .write()
                .insert(key, UnixEntry(UnixEntryInner::Datagram(send_channel)));
        }
        self.addr = Some((bound_addr, task.global.clone()));
        if self.read_shutdown {
            recv_channel.shutdown();
        }
        self.recv_channel = Some(recv_channel);
        Ok(())
    }

    fn shutdown(&mut self, how: ShutdownHow) {
        let mut events = Events::empty();
        if how.is_shutdown_read() {
            self.read_shutdown = true;
            if let Some(recv_channel) = &self.recv_channel {
                recv_channel.shutdown();
            }
            events |= Events::IN | Events::RDHUP;
        }
        if how.is_shutdown_write() {
            self.write_shutdown = true;
            if let Some((connected_send_channel, _)) = &self.connected_send_channel {
                connected_send_channel.shutdown();
            }
            events |= Events::OUT | Events::HUP;
        }
        self.pollee.notify_observers(events);
    }
}

impl<Platform: ShimPlatform, FS: ShimFS> UnixDatagram<Platform, FS> {
    fn new() -> Self {
        Self {
            inner: RwLock::new(UnixDatagramInner {
                addr: None,
                recv_channel: None,
                connected_send_channel: None,
                read_shutdown: false,
                write_shutdown: false,
                pollee: Arc::new(Pollee::new()),
            }),
        }
    }

    fn new_pair() -> (UnixDatagram<Platform, FS>, UnixDatagram<Platform, FS>) {
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
                    connected_send_channel: Some((send_channel_peer, UnixSocketAddr::Unnamed)),
                    read_shutdown: false,
                    write_shutdown: false,
                    pollee: pollee1,
                }),
            },
            UnixDatagram {
                inner: RwLock::new(UnixDatagramInner {
                    addr: None,
                    recv_channel: Some(recv_channel_peer),
                    connected_send_channel: Some((send_channel, UnixSocketAddr::Unnamed)),
                    read_shutdown: false,
                    write_shutdown: false,
                    pollee: pollee2,
                }),
            },
        )
    }

    /// Binds this socket to the given address.
    fn bind(&self, task: &Task<Platform, FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        self.inner.write().bind(task, addr)
    }

    /// Looks up a socket address and returns its write endpoint.
    fn lookup(
        &self,
        task: &Task<Platform, FS>,
        addr: UnixSocketAddr,
    ) -> Result<WriteEnd<Platform, DatagramMessage>, Errno> {
        let guard = task.global.unix_addr_table.read();
        let Some(key) = addr.to_key() else {
            return Err(Errno::EINVAL);
        };
        let Some(entry) = guard.get(&key) else {
            return Err(Errno::ECONNREFUSED);
        };
        // check if we can reach the address
        let _ = addr.check_reachable(task)?;
        match &entry.0 {
            UnixEntryInner::Stream(_) => Err(Errno::EPROTOTYPE),
            UnixEntryInner::Datagram(send_channel) => Ok(send_channel.clone()),
            // Bound but not (yet) actually receiving: nothing is there to
            // send to, matching Linux's ECONNREFUSED for an unreachable peer.
            UnixEntryInner::Reserved(_) => Err(Errno::ECONNREFUSED),
        }
    }

    /// Connects this socket to a default peer address.
    ///
    /// Subsequent sends without an address will use this peer.
    fn connect(&self, task: &Task<Platform, FS>, addr: UnixSocketAddr) -> Result<(), Errno> {
        let send_channel = self.lookup(task, addr.clone())?;
        let mut inner = self.inner.write();
        if inner.write_shutdown {
            send_channel.shutdown();
        }
        inner.connected_send_channel = Some((send_channel, addr));
        Ok(())
    }

    fn recvfrom(
        &self,
        cx: &WaitContext<'_, Platform>,
        timeout: Option<Duration>,
        buf: &mut [u8],
        is_nonblocking: bool,
        mut source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<(usize, Ucred), Errno> {
        let res = cx
            .with_timeout(timeout)
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
            .map_err(Errno::from);
        // - Non-blocking + self-shutdown(SHUT_RD) with empty queue: Linux returns EAGAIN
        //   instead of EOF (datagram boundaries; no message synthesized for the absent peer).
        // - SO_RCVTIMEO expiry on a blocking recv: Linux returns EAGAIN, not ETIMEDOUT
        //   (the latter is reserved for connect-style timeouts).
        match res {
            Err(Errno::ESHUTDOWN) if is_nonblocking => Err(Errno::EAGAIN),
            Err(Errno::ETIMEDOUT) => Err(Errno::EAGAIN),
            other => other,
        }
    }

    // Sends data to the specified or connected peer.
    ///
    /// If `addr` is provided, sends to that address. Otherwise, uses the
    /// connected peer (set via `connect()`).
    fn sendto(
        &self,
        task: &Task<Platform, FS>,
        timeout: Option<Duration>,
        buf: &[u8],
        credentials: Ucred,
        is_nonblocking: bool,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        let source = self.get_local_addr();
        let connected_send_channel = {
            let inner = self.inner.read();
            if inner.write_shutdown {
                return Err(Errno::EPIPE);
            }
            inner
                .connected_send_channel
                .as_ref()
                .map(|(send_channel, _)| send_channel.clone())
        };

        let send_channel = if let Some(addr) = addr {
            self.lookup(task, addr)?
        } else if let Some(connected_send_channel) = connected_send_channel {
            connected_send_channel
        } else {
            return Err(Errno::ENOTCONN);
        };
        send_channel.write(
            &task.wait_cx(),
            timeout,
            DatagramMessage {
                data: buf.to_vec(),
                source,
                credentials,
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
            .map(|(_, addr)| addr.clone())
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::empty();
        let inner = self.inner.read();
        let recv_shutdown = inner.read_shutdown;
        let send_shutdown = inner.write_shutdown;

        if recv_shutdown {
            events |= Events::IN | Events::RDHUP;
        } else if let Some(recv_channel) = &inner.recv_channel
            && !recv_channel.is_empty()
        {
            events |= Events::IN;
        }

        if let Some((connected_send_channel, _)) = &inner.connected_send_channel {
            if !connected_send_channel.is_full() {
                events |= Events::OUT;
            }
        } else if !send_shutdown {
            // If not connected, allow to sendto any address?
            events |= Events::OUT;
        }
        // Linux reports POLLHUP on a dgram fd only when *both* local directions are
        // shut down (peer-side shutdown is invisible since dgrams are connectionless).
        if recv_shutdown && send_shutdown {
            events |= Events::HUP;
        }
        events
    }

    fn shutdown(&self, how: ShutdownHow) {
        let mut inner = self.inner.write();
        inner.shutdown(how);
    }
}

enum UnixSocketInner<Platform: ShimPlatform, FS: ShimFS> {
    Stream(UnixStream<Platform, FS>),
    Datagram(UnixDatagram<Platform, FS>),
}
pub(crate) struct UnixSocket<Platform: ShimPlatform, FS: ShimFS> {
    inner: UnixSocketInner<Platform, FS>,
    sock_type: SockType,
    status: AtomicU32,
    options: Mutex<Platform, SocketOptions>,
}

impl<Platform: ShimPlatform, FS: ShimFS> UnixSocket<Platform, FS> {
    fn new_with_inner(
        inner: UnixSocketInner<Platform, FS>,
        sock_type: SockType,
        flags: SockFlags,
    ) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(SockFlags::NONBLOCK));
        Self {
            inner,
            sock_type,
            status: AtomicU32::new(status.bits()),
            options: litebox::sync::Mutex::new(SocketOptions::default()),
        }
    }

    pub(super) fn new(
        sock_type: SockType,
        flags: SockFlags,
        _task: &Task<Platform, FS>,
    ) -> Option<Self> {
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
        Some(Self::new_with_inner(inner, sock_type, flags))
    }

    pub(super) fn bind(
        &self,
        task: &Task<Platform, FS>,
        addr: UnixSocketAddr,
    ) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.bind(task, addr),
            UnixSocketInner::Datagram(datagram) => datagram.bind(task, addr),
        }
    }

    pub(super) fn listen(
        &self,
        backlog: u16,
        global: &Arc<GlobalState<Platform, FS>>,
        task: &Task<Platform, FS>,
    ) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.listen(backlog, global, task_ucred(task)),
            UnixSocketInner::Datagram(_) => Err(Errno::EOPNOTSUPP),
        }
    }

    pub(super) fn connect(
        &self,
        task: &Task<Platform, FS>,
        addr: UnixSocketAddr,
    ) -> Result<(), Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.connect(task, addr, self.get_status().contains(OFlags::NONBLOCK))
            }
            UnixSocketInner::Datagram(datagram) => datagram.connect(task, addr),
        }
    }

    pub(super) fn accept(
        &self,
        cx: &WaitContext<'_, Platform>,
        flags: SockFlags,
        peer: Option<&mut UnixSocketAddr>,
    ) -> Result<UnixSocket<Platform, FS>, Errno> {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                let accepted = stream.accept(
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
        task: &Task<Platform, FS>,
        buf: &[u8],
        flags: SendFlags,
        addr: Option<UnixSocketAddr>,
    ) -> Result<usize, Errno> {
        self.sendmsg(task, buf, flags, addr, Vec::new(), None)
    }

    /// `credentials` is an explicit, already-validated `SCM_CREDENTIALS` the
    /// sender attached; without one the sender's own process id and real ids
    /// travel with the data, so a `SO_PASSCRED` receiver always learns who
    /// sent what (Linux `maybe_add_creds`).
    pub(super) fn sendmsg(
        &self,
        task: &Task<Platform, FS>,
        buf: &[u8],
        flags: SendFlags,
        addr: Option<UnixSocketAddr>,
        rights: Vec<TransferredFd<Platform, FS>>,
        credentials: Option<Ucred>,
    ) -> Result<usize, Errno> {
        let supported_flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported sendmsg flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let is_nonblocking =
            flags.contains(SendFlags::DONTWAIT) || self.get_status().contains(OFlags::NONBLOCK);
        let timeout = self.options.lock().send_timeout;
        let credentials = credentials.unwrap_or_else(|| task_send_ucred(task));
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.sendto(
                &task.wait_cx(),
                timeout,
                Message {
                    data: buf.to_vec(),
                    rights,
                    credentials,
                },
                is_nonblocking,
                addr,
            ),
            UnixSocketInner::Datagram(datagram) => {
                if !rights.is_empty() {
                    return Err(Errno::EOPNOTSUPP);
                }
                datagram.sendto(task, timeout, buf, credentials, is_nonblocking, addr)
            }
        }
    }

    pub(super) fn recvfrom(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<usize, Errno> {
        self.recvmsg(cx, buf, flags, source_addr)
            .map(|result| result.size)
    }

    pub(super) fn recvmsg(
        &self,
        cx: &WaitContext<'_, Platform>,
        buf: &mut [u8],
        flags: ReceiveFlags,
        source_addr: Option<&mut Option<UnixSocketAddr>>,
    ) -> Result<RecvResult<Platform, FS>, Errno> {
        let supported_flags = ReceiveFlags::DONTWAIT | ReceiveFlags::TRUNC;
        if flags.intersects(supported_flags.complement()) {
            log_unsupported!("Unsupported recvmsg flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
        let is_nonblocking =
            flags.contains(ReceiveFlags::DONTWAIT) || self.get_status().contains(OFlags::NONBLOCK);
        let (timeout, pass_cred) = {
            let options = self.options.lock();
            (options.recv_timeout, options.pass_cred)
        };
        let ret = match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.recvfrom(cx, timeout, buf, is_nonblocking, pass_cred, source_addr)
            }
            UnixSocketInner::Datagram(datagram) => datagram
                .recvfrom(cx, timeout, buf, is_nonblocking, source_addr)
                .map(|(size, credentials)| RecvResult {
                    size,
                    rights: Vec::new(),
                    credentials: pass_cred.then_some(credentials),
                }),
        };
        match ret {
            // EOF: Linux still runs `scm_recv`, so a `SO_PASSCRED` receiver gets an
            // `SCM_CREDENTIALS` naming nobody (pid 0, overflow ids).
            Err(Errno::ESHUTDOWN) => Ok(RecvResult {
                size: 0,
                rights: Vec::new(),
                credentials: pass_cred.then_some(UNSET_UCRED),
            }),
            other => other,
        }
    }

    pub(super) fn get_local_addr(&self) -> UnixSocketAddr {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.get_local_addr(),
            UnixSocketInner::Datagram(datagram) => datagram.get_local_addr(),
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
        task: &Task<Platform, FS>,
    ) -> Option<(UnixSocket<Platform, FS>, UnixSocket<Platform, FS>)> {
        match ty {
            SockType::Stream | SockType::SeqPacket => {
                let cred = task_ucred(task);
                let (conn1, conn2) = UnixConnectedStream::new_pair(
                    None,
                    cred,
                    None,
                    None,
                    cred,
                    None,
                    false,
                    false,
                    matches!(ty, SockType::SeqPacket),
                );
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
                let (datagram1, datagram2) = UnixDatagram::new_pair();
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
        global: &GlobalState<Platform, FS>,
        optname: SocketOptionName,
        optval: UserPtr<u8>,
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
                // SO_PASSCRED: from now on every recvmsg on this socket carries an
                // SCM_CREDENTIALS control message naming the sender.
                SocketOption::PASSCRED => {
                    let enabled = super::read_from_user::<u32, Platform>(optval, optlen)? != 0;
                    self.options.lock().pass_cred = enabled;
                    Ok(())
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
            SocketOptionName::IP(_) | SocketOptionName::TCP(_) => Err(Errno::EOPNOTSUPP),
        }
    }
    pub(super) fn getsockopt(
        &self,
        global: &GlobalState<Platform, FS>,
        optname: SocketOptionName,
        optval: UserPtrMut<u8>,
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
                SocketOption::PASSCRED => u32::from(self.options.lock().pass_cred),
                SocketOption::RCVBUF | SocketOption::SNDBUF => UNIX_BUF_SIZE.trunc(),
                SocketOption::PEERCRED => match &self.inner {
                    UnixSocketInner::Stream(stream) => {
                        let ucred = stream.get_peer_cred().unwrap_or(Ucred {
                            pid: 0,
                            uid: u32::MAX,
                            gid: u32::MAX,
                        });
                        return super::write_to_user::<_, Platform>(ucred, optval, len);
                    }
                    UnixSocketInner::Datagram(_) => {
                        log_unsupported!("get PEERCRED for unix datagram socket");
                        return Err(Errno::EOPNOTSUPP);
                    }
                },
            },
            SocketOptionName::IP(_) | SocketOptionName::TCP(_) => return Err(Errno::EOPNOTSUPP),
        };
        super::write_to_user::<_, Platform>(val, optval, len)
    }

    pub(super) fn shutdown(&self, how: ShutdownHow) {
        match &self.inner {
            UnixSocketInner::Stream(stream) => stream.shutdown(how),
            UnixSocketInner::Datagram(datagram) => datagram.shutdown(how),
        }
    }

    super::common_functions_for_file_status!();
}

impl<Platform: ShimPlatform, FS: ShimFS> IOPollable for UnixSocket<Platform, FS> {
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

    fn unregister_observer(&self, observer: Weak<dyn litebox::event::observer::Observer<Events>>) {
        match &self.inner {
            UnixSocketInner::Stream(stream) => {
                stream.unregister_observer(observer);
            }
            UnixSocketInner::Datagram(datagram) => {
                datagram.inner.read().pollee.unregister_observer(observer);
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

pub(crate) struct UnixEntry<Platform: ShimPlatform, FS: ShimFS>(UnixEntryInner<Platform, FS>);
enum UnixEntryInner<Platform: ShimPlatform, FS: ShimFS> {
    Stream(Arc<Backlog<Platform, FS>>),
    Datagram(WriteEnd<Platform, DatagramMessage>),
    /// A placeholder claimed by `bind()` (autobind, explicit path, or
    /// explicit abstract) before the socket has gone on to `listen()` or
    /// (for datagram sockets) finished its atomic bind. Nothing can lookup
    /// or connect through a `Reserved` slot -- it exists purely to make the
    /// address collide with any other bind attempt, exactly as a live
    /// `Stream`/`Datagram` entry would.
    Reserved(Arc<ReservationToken>),
}

/// Type alias for the global Unix socket address table.
pub(crate) type UnixAddrTable<Platform, FS> = BTreeMap<UnixSocketAddrKey, UnixEntry<Platform, FS>>;
