// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-owned sockets on the host's network stack, with per-socket locking.
//!
//! Calls run on the caller's thread under the socket's own `state` lock, so
//! calls on different sockets run in parallel and none waits for network
//! readiness. One event thread turns the host's socket events into cached
//! readiness under the same lock. The host's sockets and events are behind
//! the `host` module, so the rest of the provider is the same on every host.
//! State shared between sockets (bindings,
//! listener queues, peer links, and quotas) lives in the provider-wide
//! `topology` lock, and a socket reaches another socket only through that
//! socket's `inbox`.
//!
//! Locks are taken in this order: a socket's `state`, then `topology`, then
//! one leaf (`registry`, `udp_ports`, or any socket's `inbox`). A thread holds
//! at most one socket's `state`, except that accept also holds the new
//! socket's. It never takes a `state` while holding `topology` or a leaf, and
//! never holds two leaves at once. Every readiness publication goes through
//! the socket's `inbox`, so the published value always combines the socket's
//! own readiness with what other sockets posted.
//!
//! An internal connection between guest sockets is an in-memory
//! [`stream`](litebox_broker_core::socket::stream) rather than a host
//! socket. Each end's waker posts its socket's token for the event thread,
//! which applies it like a host event. A stream's lock and the posted-token
//! lock are innermost: a thread may take them under any other lock, but takes
//! nothing while holding them, and wakers run only after the stream's lock is
//! released.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::SocketAddrV4;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{
    Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use litebox_broker_core::readiness::ReadinessRegistration;
use litebox_broker_core::socket::stream::StreamWaker;
use litebox_broker_core::socket::{
    AcceptedPlatformSocket, GuestSocketBinding, GuestSourceLease, PlatformConnectError,
    PlatformDatagramReceive, PlatformSocket, PlatformSocketStatus, PlatformStreamReceive,
    SocketProvider,
};
use litebox_broker_core::{BrokerError, Result as BrokerResult};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{
    AddressFamily, CreateSocketRequest, IpProtocol, MAX_UDP_DATAGRAM_SIZE, ReceiveFlags,
    ReceiveFromFlags, SendFlags, ShutdownMode, SocketConnectionStatus, SocketError,
    SocketOptionName, SocketOptionValue, SocketOutcome, SocketType,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

mod direct;
mod host;
mod tcp;
mod udp;

use direct::{RawParts, receive_into, send_from};
use host::{
    Errno, Events, HostEvents, HostSocket, Interest, Poller, WAKE_TOKEN, Waiter,
    broker_resource_error_from_errno,
};
use tcp::{
    AcceptedEndpoints, ReceiveOutcome, TcpPendingError, TcpSocketState, TcpTopology,
    consume_pending_guest_reset, create_tcp_transport, guest_reset_pending, handle_socket_event,
    tcp_peek_buffer,
};
use udp::{
    ProcessCounters, QueueCounter, UDP_EVENT_TOKEN_FLAG, UdpInbox, UdpPeer, UdpPorts,
    UdpReceiveOrigin, UdpSocketState, UdpTopology,
};

/// Most host events the event thread collects per wait.
const MAX_HOST_EVENTS: usize = 64;
/// Longest the event thread waits before retrying events for busy sockets.
const DEFERRED_EVENT_RETRY: Duration = Duration::from_millis(1);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("socket provider lock poisoned")
}

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().expect("socket provider lock poisoned")
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().expect("socket provider lock poisoned")
}

/// Userland socket provider on the host's network stack.
///
/// Calls run on the broker's request workers under each socket's own lock and
/// never wait for network readiness. One event thread turns the host's socket
/// events into cached readiness.
pub struct UserlandSocketProvider {
    core: Arc<ProviderCore>,
}

impl UserlandSocketProvider {
    /// Starts a provider with global and per-process socket limits.
    pub fn new(max_sockets: usize, max_sockets_per_process: usize) -> IoResult<Self> {
        Ok(Self {
            core: ProviderCore::start(max_sockets, max_sockets_per_process)?,
        })
    }
}

impl SocketProvider for UserlandSocketProvider {
    fn create(
        &self,
        process_authority: ProcessId,
        request: CreateSocketRequest,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<Arc<dyn PlatformSocket>> {
        let kind = socket_kind(request).ok_or(BrokerError::UnsupportedOperation)?;
        let socket = UserlandSocket::new(&self.core, process_authority, kind, readiness)?;
        let mut state = lock(&socket.state);
        self.core.charge_socket(process_authority)?;
        if kind == SocketKind::Udp {
            socket.inbox.lock().set_own(ReadinessFlags::WRITE);
        }
        if let Err(error) = self.core.register(&socket) {
            self.core.release_socket_charge(process_authority);
            return Err(error);
        }
        state.closed = false;
        drop(state);
        Ok(socket)
    }

    fn close_process(&self, process_authority: ProcessId) {
        self.core.close_process(process_authority);
    }
}

/// Provider-wide state shared by every socket and the event thread.
struct ProviderCore {
    /// Watches host sockets for the event thread.
    poller: Arc<Poller>,
    /// Tokens of internal endpoints whose streams changed.
    posted: Arc<PostedEvents>,
    next_socket_id: AtomicU64,
    next_udp_event_token: AtomicU64,
    max_sockets: usize,
    max_sockets_per_process: usize,
    /// Bindings, listener queues, peer links, and quota accounting.
    topology: Mutex<Topology>,
    /// Maps event tokens to sockets for the event thread.
    registry: RwLock<Registry>,
    /// Host UDP ports the broker owns or sends to.
    udp_ports: RwLock<UdpPorts>,
    /// Datagrams and bytes queued between guest UDP sockets broker-wide.
    udp_queued: Arc<QueueCounter>,
    /// Set under the `registry` write lock once the event thread fails.
    failed: AtomicBool,
    thread: Mutex<Option<JoinHandle<()>>>,
    /// Test callback run at every [`HookPoint`].
    #[cfg(test)]
    hook: RwLock<Option<Hook>>,
}

/// Socket counts, guest bindings, and peer links shared between sockets.
#[derive(Default)]
struct Topology {
    socket_count: usize,
    processes: HashMap<ProcessId, ProcessAccount>,
    tcp: TcpTopology,
    udp: UdpTopology,
}

/// Socket quota and UDP accounting for one process instance.
///
/// Processes are ownership domains, not guest network namespaces.
struct ProcessAccount {
    live_socket_count: usize,
    pending_guest_connection_count: usize,
    udp_external_peer_count: usize,
    udp_local_peer_count: usize,
    udp_counters: Arc<ProcessCounters>,
}

/// Live sockets by ID and native UDP endpoints by event token.
#[derive(Default)]
struct Registry {
    sockets: HashMap<u64, Weak<UserlandSocket>>,
    udp_tokens: HashMap<u64, u64>,
}

/// Fatal failure that stops the event thread.
#[derive(Debug)]
enum EventFailure {
    Io(Errno),
    Broker(BrokerError),
}

impl fmt::Display for EventFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Broker(error) => write!(formatter, "broker error: {error:?}"),
        }
    }
}

/// What the event thread did with one event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dispatch {
    Applied,
    /// The socket was busy; the event is retried after the batch.
    Deferred,
    /// The socket waits for data its host does not report; an empty event
    /// is retried after the batch.
    Polled,
    /// The socket is gone or closed.
    Dropped,
}

/// Points where tests can observe or pause provider threads.
///
/// Socket calls and the event thread can work on one socket at once, so some
/// races have windows too narrow for stress tests to hit reliably. Tests
/// install a hook that runs at each point, so a test can hold one thread at a
/// point while another acts, which makes each race happen on every run.
/// Outside tests the hook is a no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HookPoint {
    /// A call on the socket released its `state`.
    Unlocked(u64),
    /// A TCP receive holds the socket's `state` and is about to receive.
    Receiving(u64),
    /// A TCP receive would block and is about to clear READ.
    Eagain(u64),
    /// A host socket was added to the poller, or an internal endpoint began
    /// posting events, with this token.
    Watched(u64),
    /// Retiring the socket detached it from the guest topology and is about
    /// to close its descriptor.
    Unlinked(u64),
    /// Retiring the socket closed its internal endpoint.
    EndpointClosed(u64),
    /// The event thread harvested an event for this token.
    Harvested(u64),
    /// The event thread finished an event for this token.
    Handled(u64, Dispatch),
    /// The event thread finished a batch of events and is about to wait for
    /// the next.
    Waiting,
}

#[cfg(test)]
type Hook = Arc<dyn Fn(HookPoint) + Send + Sync>;

/// Tokens that internal stream ends posted for the event thread, which they
/// wake through the poller.
struct PostedEvents {
    /// Holds room for every socket, so posting does not allocate.
    tokens: Mutex<HashSet<u64>>,
    /// A post failed to allocate, so its event was lost.
    overflowed: AtomicBool,
    /// A wake failed, so posted tokens may wait with no wake to report them.
    wake_failed: AtomicBool,
    poller: Arc<Poller>,
    /// Makes every wake fail, for tests.
    #[cfg(test)]
    fail_wakes: AtomicBool,
}

impl PostedEvents {
    /// Posts an event for `token`, waking the event thread unless an earlier
    /// post it has not yet taken already did.
    ///
    /// A wake fails only when the host is short of resources, such as when
    /// Windows cannot queue a completion. Later posts then wake again, and
    /// the event thread takes the tokens at its next batch.
    fn post(&self, token: u64) {
        let mut tokens = lock(&self.tokens);
        let first = tokens.is_empty();
        if tokens.try_reserve(1).is_ok() {
            tokens.insert(token);
        } else {
            self.overflowed.store(true, Ordering::Release);
        }
        drop(tokens);
        if (first || self.take_wake_failure()) && self.wake().is_err() {
            self.wake_failed.store(true, Ordering::Release);
        }
    }

    /// Wakes the event thread.
    fn wake(&self) -> IoResult<()> {
        #[cfg(test)]
        if self.fail_wakes.load(Ordering::Relaxed) {
            return Err(Error::other("test wake failure"));
        }
        self.poller.wake()
    }

    /// Returns whether a wake failed since the last call.
    fn take_wake_failure(&self) -> bool {
        self.wake_failed.load(Ordering::Acquire) && self.wake_failed.swap(false, Ordering::AcqRel)
    }

    /// Swaps the posted tokens with `tokens`, which must be empty, so both
    /// sets keep their room.
    fn take_into(&self, tokens: &mut HashSet<u64>) -> Result<(), EventFailure> {
        core::mem::swap(&mut *lock(&self.tokens), tokens);
        if self.overflowed.load(Ordering::Acquire) {
            return Err(EventFailure::Broker(BrokerError::OutOfMemory));
        }
        Ok(())
    }
}

/// Allocates an empty token set with room for `capacity` tokens.
fn token_set(capacity: usize) -> IoResult<HashSet<u64>> {
    let mut tokens = HashSet::new();
    tokens
        .try_reserve(capacity)
        .map_err(|_| Error::new(ErrorKind::OutOfMemory, "posted event allocation failed"))?;
    Ok(tokens)
}

impl ProviderCore {
    fn start(max_sockets: usize, max_sockets_per_process: usize) -> IoResult<Arc<Self>> {
        let (poller, waiter) = Poller::new()?;
        let poller = Arc::new(poller);
        let mut registry = Registry::default();
        registry
            .sockets
            .try_reserve(max_sockets)
            .map_err(|_| Error::new(ErrorKind::OutOfMemory, "socket table allocation failed"))?;
        let posted = Arc::new(PostedEvents {
            tokens: Mutex::new(token_set(max_sockets)?),
            overflowed: AtomicBool::new(false),
            wake_failed: AtomicBool::new(false),
            poller: Arc::clone(&poller),
            #[cfg(test)]
            fail_wakes: AtomicBool::new(false),
        });
        let taken = token_set(max_sockets)?;
        let core = Arc::new(Self {
            poller,
            posted,
            next_socket_id: AtomicU64::new(1),
            next_udp_event_token: AtomicU64::new(1),
            max_sockets,
            max_sockets_per_process,
            topology: Mutex::new(Topology::default()),
            registry: RwLock::new(registry),
            udp_ports: RwLock::new(UdpPorts::default()),
            udp_queued: Arc::new(QueueCounter::default()),
            failed: AtomicBool::new(false),
            thread: Mutex::new(None),
            #[cfg(test)]
            hook: RwLock::new(None),
        });
        let weak = Arc::downgrade(&core);
        let (started, startup) = sync_channel(1);
        let thread = thread::Builder::new()
            .name("litebox-broker-socket-events".into())
            .spawn(move || {
                // Host events need not be `Send`, so the thread allocates its
                // own event buffer.
                let events = Events::with_capacity(MAX_HOST_EVENTS);
                let allocated = events.is_some();
                if started.send(allocated).is_ok()
                    && let Some(events) = events
                {
                    run_event_thread(&weak, waiter, events, taken);
                }
            })?;
        match startup.recv() {
            Ok(true) => {}
            Ok(false) => {
                let _ = thread.join();
                return Err(Error::new(
                    ErrorKind::OutOfMemory,
                    "socket event allocation failed",
                ));
            }
            Err(_) => {
                let _ = thread.join();
                return Err(Error::other("socket event thread failed during startup"));
            }
        }
        *lock(&core.thread) = Some(thread);
        Ok(core)
    }

    #[cfg(test)]
    fn hook(&self, point: HookPoint) {
        let hook = read_lock(&self.hook).clone();
        if let Some(hook) = hook {
            hook(point);
        }
    }

    #[cfg(not(test))]
    #[inline]
    #[allow(clippy::unused_self)]
    fn hook(&self, _point: HookPoint) {}

    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn allocate_socket_id(&self) -> BrokerResult<u64> {
        self.next_socket_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                (id < UDP_EVENT_TOKEN_FLAG - 1).then_some(id + 1)
            })
            .map_err(|_| BrokerError::ResourceExhausted)
    }

    /// Watches `socket` for `interest` under `token`.
    fn watch_host_socket(
        &self,
        socket: &mut HostSocket,
        token: u64,
        interest: Interest,
    ) -> BrokerResult<()> {
        self.poller
            .add(socket, token, interest)
            .map_err(broker_error_from_errno)?;
        self.hook(HookPoint::Watched(token));
        Ok(())
    }

    /// Stops watching `socket` before it closes.
    fn unwatch_host_socket(&self, socket: &mut HostSocket) {
        self.poller.delete(socket);
    }

    /// Returns a stream waker that posts an event for `token`.
    fn stream_waker(&self, token: u64) -> StreamWaker {
        let posted = Arc::clone(&self.posted);
        Arc::new(move || posted.post(token))
    }

    /// Posts the first event for an internal endpoint, whose stream posts the
    /// later ones, so the event thread applies its current state.
    fn watch_internal(&self, token: u64) {
        self.posted.post(token);
        self.hook(HookPoint::Watched(token));
    }

    fn charge_socket(&self, process_authority: ProcessId) -> BrokerResult<()> {
        lock(&self.topology).charge_socket(
            process_authority,
            self.max_sockets,
            self.max_sockets_per_process,
        )
    }

    fn release_socket_charge(&self, process_authority: ProcessId) {
        lock(&self.topology).release_socket(process_authority);
    }

    /// Makes `socket` reachable by the event thread.
    ///
    /// Fails once the provider has failed, so every socket is either
    /// collected by [`Self::fail`] or never opened.
    fn register(&self, socket: &Arc<UserlandSocket>) -> BrokerResult<()> {
        let mut registry = write_lock(&self.registry);
        if self.failed() {
            return Err(BrokerError::Internal);
        }
        registry
            .sockets
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        registry.sockets.insert(socket.id, Arc::downgrade(socket));
        Ok(())
    }

    fn unregister(&self, id: u64) {
        write_lock(&self.registry).sockets.remove(&id);
    }

    fn close_process(&self, process_authority: ProcessId) {
        let mut topology = lock(&self.topology);
        topology.purge_connector_process_queues(process_authority);
        if let Some(process) = topology.processes.remove(&process_authority) {
            debug_assert_eq!(process.live_socket_count, 0);
            debug_assert_eq!(process.pending_guest_connection_count, 0);
            debug_assert_eq!(process.udp_external_peer_count, 0);
            debug_assert_eq!(process.udp_local_peer_count, 0);
        }
    }

    /// Fails every socket after the event thread fails.
    ///
    /// Each socket publishes ERROR as its last readiness, and later calls
    /// return `Internal`.
    fn fail(&self) {
        // Take the map rather than copying it, so failing cannot itself fail
        // to allocate.
        let sockets = {
            let mut registry = write_lock(&self.registry);
            self.failed.store(true, Ordering::Release);
            core::mem::take(&mut registry.sockets)
        };
        for socket in sockets.into_values() {
            if let Some(socket) = socket.upgrade() {
                socket.close(true);
            }
        }
    }

    /// Applies one batch of host events, and the events internal endpoints
    /// posted, then retries deferred ones.
    fn handle_events(
        &self,
        events: &Events,
        waiter: &Waiter,
        deferred: &mut HashMap<u64, HostEvents>,
        posted: &mut HashSet<u64>,
    ) -> Result<(), EventFailure> {
        for (token, flags) in events.iter() {
            if token == WAKE_TOKEN {
                // Draining first means a post after the take wakes again.
                waiter.drain_wake().map_err(EventFailure::Io)?;
                self.take_posted(deferred, posted)?;
                continue;
            }
            self.harvest(token, flags, deferred)?;
        }
        // A failed wake left posted tokens that no wake reports.
        if self.posted.take_wake_failure() {
            self.take_posted(deferred, posted)?;
        }
        for (token, flags) in core::mem::take(deferred) {
            self.dispatch(token, flags, deferred)?;
        }
        Ok(())
    }

    /// Dispatches an event for each token internal endpoints posted.
    fn take_posted(
        &self,
        deferred: &mut HashMap<u64, HostEvents>,
        posted: &mut HashSet<u64>,
    ) -> Result<(), EventFailure> {
        self.posted.take_into(posted)?;
        for token in posted.drain() {
            self.harvest(token, HostEvents::empty(), deferred)?;
        }
        Ok(())
    }

    /// Dispatches a harvested event, merged with any deferred one for its
    /// token.
    fn harvest(
        &self,
        token: u64,
        flags: HostEvents,
        deferred: &mut HashMap<u64, HostEvents>,
    ) -> Result<(), EventFailure> {
        self.hook(HookPoint::Harvested(token));
        let flags = flags | deferred.remove(&token).unwrap_or_default();
        self.dispatch(token, flags, deferred)
    }

    fn dispatch(
        &self,
        token: u64,
        flags: HostEvents,
        deferred: &mut HashMap<u64, HostEvents>,
    ) -> Result<(), EventFailure> {
        let socket = {
            let registry = read_lock(&self.registry);
            let id = if token & UDP_EVENT_TOKEN_FLAG == 0 {
                Some(token)
            } else {
                registry.udp_tokens.get(&token).copied()
            };
            id.and_then(|id| registry.sockets.get(&id))
                .and_then(Weak::upgrade)
        };
        // Drop the socket only after its lock is released: dropping the last
        // reference retires it.
        let outcome = match &socket {
            Some(socket) => socket.handle_event(token, flags),
            None => Ok(Dispatch::Dropped),
        };
        drop(socket);
        let outcome = outcome.map_err(EventFailure::Broker)?;
        let retry = match outcome {
            Dispatch::Deferred => Some(flags),
            Dispatch::Polled => Some(HostEvents::empty()),
            Dispatch::Applied | Dispatch::Dropped => None,
        };
        if let Some(flags) = retry {
            deferred
                .try_reserve(1)
                .map_err(|_| EventFailure::Broker(BrokerError::OutOfMemory))?;
            deferred.insert(token, flags);
        }
        self.hook(HookPoint::Handled(token, outcome));
        Ok(())
    }
}

impl Drop for ProviderCore {
    fn drop(&mut self) {
        // Wake the event thread so it observes that the provider is gone. A
        // thread that failed to wake may wait forever, so it is not joined.
        let woken = self.posted.wake().is_ok();
        let thread = self
            .thread
            .get_mut()
            .expect("socket provider lock poisoned")
            .take();
        // The event thread drops the last reference only when it retires the
        // last socket, and then exits on its own.
        if woken
            && let Some(thread) = thread
            && thread.thread().id() != thread::current().id()
            && thread.join().is_err()
        {
            std::eprintln!("broker socket event thread panicked");
        }
    }
}

impl Topology {
    /// Charges a socket to `process_authority` if the global and per-process
    /// quotas allow it.
    fn charge_socket(
        &mut self,
        process_authority: ProcessId,
        max_sockets: usize,
        max_sockets_per_process: usize,
    ) -> BrokerResult<()> {
        if self
            .socket_count
            .checked_add(self.tcp.queued_guest_connection_count)
            .is_none_or(|count| count >= max_sockets)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        let process = self.processes.get(&process_authority);
        let next_live_socket_count = process
            .map_or(0, |process| process.live_socket_count)
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        if next_live_socket_count
            .checked_add(process.map_or(0, |process| process.pending_guest_connection_count))
            .is_none_or(|count| count > max_sockets_per_process)
        {
            return Err(BrokerError::ResourceExhausted);
        }
        if process.is_none() {
            self.processes
                .try_reserve(1)
                .map_err(|_| BrokerError::OutOfMemory)?;
            self.processes.insert(
                process_authority,
                ProcessAccount {
                    live_socket_count: 0,
                    pending_guest_connection_count: 0,
                    udp_external_peer_count: 0,
                    udp_local_peer_count: 0,
                    udp_counters: Arc::new(ProcessCounters::default()),
                },
            );
        }
        self.process_mut(process_authority).live_socket_count = next_live_socket_count;
        self.socket_count += 1;
        Ok(())
    }

    fn release_socket(&mut self, process_authority: ProcessId) {
        let process = self.process_mut(process_authority);
        process.live_socket_count = process
            .live_socket_count
            .checked_sub(1)
            .expect("process socket count underflow");
        self.socket_count = self
            .socket_count
            .checked_sub(1)
            .expect("socket count underflow");
    }

    fn process_mut(&mut self, process_authority: ProcessId) -> &mut ProcessAccount {
        self.processes
            .get_mut(&process_authority)
            .expect("socket process account missing")
    }
}

fn run_event_thread(
    core: &Weak<ProviderCore>,
    mut waiter: Waiter,
    mut events: Events,
    mut posted: HashSet<u64>,
) {
    let mut deferred = HashMap::new();
    loop {
        let timeout = (!deferred.is_empty()).then_some(DEFERRED_EVENT_RETRY);
        let wait_result = waiter.wait(&mut events, timeout);
        let Some(core) = core.upgrade() else {
            return;
        };
        let result = match wait_result {
            Ok(()) => core.handle_events(&events, &waiter, &mut deferred, &mut posted),
            Err(Errno::INTR) => Ok(()),
            Err(error) => Err(EventFailure::Io(error)),
        };
        if let Err(error) = result {
            std::eprintln!("broker socket event thread failed: {error}");
            core.fail();
            return;
        }
        core.hook(HookPoint::Waiting);
    }
}

/// Broker-core-facing handle for one socket.
struct UserlandSocket {
    id: u64,
    process_authority: ProcessId,
    core: Arc<ProviderCore>,
    state: Mutex<SocketState>,
    inbox: Arc<SocketInbox>,
}

impl UserlandSocket {
    /// Allocates a closed socket; its creator opens it after charging and
    /// registering it.
    fn new(
        core: &Arc<ProviderCore>,
        process_authority: ProcessId,
        kind: SocketKind,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<Arc<Self>> {
        let id = core.allocate_socket_id()?;
        let transport = match kind {
            SocketKind::Tcp => create_tcp_transport(),
            SocketKind::Udp => SocketTransportState::Udp(UdpSocketState::default()),
        };
        Ok(Arc::new(Self {
            id,
            process_authority,
            core: Arc::clone(core),
            state: Mutex::new(SocketState {
                closed: true,
                transport,
                connection_status: SocketConnectionStatus::Unconnected,
                pending_error: None,
                read_shutdown: false,
                write_shutdown: false,
                guest_local_address: None,
            }),
            inbox: Arc::new(SocketInbox::new(readiness)),
        }))
    }

    /// Locks an open socket for a call and applies what other sockets posted.
    fn enter(&self) -> BrokerResult<SocketEntry<'_>> {
        let state = lock(&self.state);
        if state.closed || self.core.failed() {
            return Err(BrokerError::Internal);
        }
        let mut socket = SocketEntry {
            socket: self,
            state,
        };
        socket.drain_inbox()?;
        Ok(socket)
    }

    fn call<T>(
        &self,
        operation: impl FnOnce(&mut SocketEntry<'_>) -> BrokerResult<T>,
    ) -> BrokerResult<T> {
        let mut socket = self.enter()?;
        let result = operation(&mut socket);
        drop(socket);
        self.core.hook(HookPoint::Unlocked(self.id));
        result
    }

    /// Applies a host event for `token` unless a call holds the socket.
    fn handle_event(&self, token: u64, flags: HostEvents) -> BrokerResult<Dispatch> {
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(Dispatch::Deferred),
            Err(TryLockError::Poisoned(_)) => panic!("socket provider lock poisoned"),
        };
        if state.closed {
            return Ok(Dispatch::Dropped);
        }
        let mut socket = SocketEntry {
            socket: self,
            state,
        };
        socket.drain_inbox()?;
        let mut flags = flags;
        // An ERROR event may be stale by the time the event thread applies it,
        // because a call can consume the error first.
        if flags.contains(HostEvents::ERROR)
            && let Some(descriptor) = socket.event_descriptor(token)
            && !descriptor
                .error_pending()
                .map_err(broker_error_from_errno)?
        {
            flags.remove(HostEvents::ERROR);
        }
        if token & UDP_EVENT_TOKEN_FLAG == 0 {
            if handle_socket_event(&mut socket, flags)? {
                return Ok(Dispatch::Polled);
            }
        } else {
            socket.handle_udp_endpoint_event(token, flags)?;
        }
        Ok(Dispatch::Applied)
    }

    /// Locks the socket and retires it unless it already is.
    fn close(&self, failure: bool) {
        let state = lock(&self.state);
        if state.closed {
            return;
        }
        SocketEntry {
            socket: self,
            state,
        }
        .retire(failure);
    }
}

impl PlatformSocket for UserlandSocket {
    fn bind(&self, binding: GuestSocketBinding) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        self.call(|socket| socket.bind_socket(binding))
    }

    fn listen(&self, backlog: u32) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        self.call(|socket| socket.listen_socket(backlog))
    }

    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> BrokerResult<SocketOutcome<AcceptedPlatformSocket>> {
        let accepted = UserlandSocket::new(
            &self.core,
            self.process_authority,
            SocketKind::Tcp,
            readiness,
        )?;
        // A failed accept leaves `accepted` closed, so dropping it here,
        // after the listener is unlocked, has nothing left to clean up.
        match self.call(|listener| listener.accept_socket(&accepted))? {
            SocketOutcome::Completed(AcceptedEndpoints {
                local_address,
                guest_source_lease,
            }) => Ok(SocketOutcome::Completed(AcceptedPlatformSocket {
                socket: accepted,
                local_address,
                guest_source_lease,
            })),
            SocketOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn connect(
        &self,
        address: SocketAddrV4,
        guest_source_lease: Option<GuestSourceLease>,
    ) -> core::result::Result<SocketConnectionStatus, PlatformConnectError> {
        let mut socket = self
            .enter()
            .map_err(PlatformConnectError::PeerIndeterminate)?;
        let result = match socket.kind() {
            SocketKind::Udp => socket.connect_udp_socket(address),
            SocketKind::Tcp => socket.connect_tcp_destination(address, guest_source_lease),
        };
        drop(socket);
        self.core.hook(HookPoint::Unlocked(self.id));
        result
    }

    fn send(
        &self,
        data: &dyn WriteBuffer,
        _flags: SendFlags,
    ) -> BrokerResult<SocketOutcome<usize>> {
        send_from(data, |data| {
            self.call(|socket| socket.send_tcp_socket(data))
        })
    }

    fn send_to(
        &self,
        data: &dyn WriteBuffer,
        _flags: SendFlags,
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        send_from(data, |data| {
            self.call(|socket| socket.send_to_socket(data, destination))
        })
    }

    fn receive(
        &self,
        reader: ObjectHandle,
        output: &mut dyn ReadBuffer,
        flags: ReceiveFlags,
        peek_offset: u32,
        peek_length: u32,
    ) -> BrokerResult<SocketOutcome<PlatformStreamReceive>> {
        let length = output.len();
        let peek_offset =
            usize::try_from(peek_offset).map_err(|_| BrokerError::UnsupportedOperation)?;
        let peek_length =
            usize::try_from(peek_length).map_err(|_| BrokerError::UnsupportedOperation)?;
        let peek_buffer = tcp_peek_buffer(length, flags, peek_offset, peek_length)?;
        match receive_into(output, ReceiveOutcome::received, |output| {
            self.call(|socket| {
                socket.receive_tcp_socket(
                    reader,
                    output,
                    peek_buffer,
                    flags,
                    peek_offset,
                    peek_length,
                )
            })
        })? {
            ReceiveOutcome::Received(received) => Ok(SocketOutcome::Completed(
                PlatformStreamReceive::Received(received),
            )),
            ReceiveOutcome::EndOfStream => {
                Ok(SocketOutcome::Completed(PlatformStreamReceive::EndOfStream))
            }
            ReceiveOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn receive_from(
        &self,
        output: &mut dyn ReadBuffer,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<SocketOutcome<PlatformDatagramReceive>> {
        match receive_into(output, ReceiveFromOutcome::received, |output| {
            self.call(|socket| socket.receive_from_socket(output, flags))
        })? {
            ReceiveFromOutcome::Received {
                received,
                datagram_length,
                source_address,
            } => Ok(SocketOutcome::Completed(PlatformDatagramReceive {
                received,
                datagram_length,
                source_address,
            })),
            ReceiveFromOutcome::Failed(error) => Ok(SocketOutcome::Failed(error)),
        }
    }

    fn shutdown(&self, mode: ShutdownMode) -> BrokerResult<SocketOutcome<()>> {
        self.call(|socket| socket.shutdown_socket(mode))
    }

    fn set_tcp_option(&self, value: SocketOptionValue) -> BrokerResult<()> {
        self.call(|socket| socket.set_tcp_socket_option(value))
    }

    fn get_tcp_option(&self, name: SocketOptionName) -> BrokerResult<SocketOptionValue> {
        self.call(|socket| socket.get_tcp_socket_option(name))
    }

    fn status(&self) -> BrokerResult<PlatformSocketStatus> {
        self.call(status_socket)
    }

    fn retire(&self) {
        self.close(false);
    }

    fn readiness(&self) -> ReadinessFlags {
        self.inbox.readiness()
    }
}

impl Drop for UserlandSocket {
    fn drop(&mut self) {
        self.close(false);
    }
}

enum ReceiveFromOutcome {
    Received {
        /// Bytes received into the start of the output.
        received: usize,
        datagram_length: usize,
        source_address: SocketAddrV4,
    },
    Failed(SocketError),
}

impl ReceiveFromOutcome {
    /// Returns how many bytes the receive copied into its output.
    fn received(&self) -> usize {
        match self {
            Self::Received { received, .. } => *received,
            Self::Failed(_) => 0,
        }
    }
}

/// Exactly one transport-specific payload for a socket.
enum SocketTransportState {
    Tcp(TcpSocketState),
    Udp(UdpSocketState),
}

/// Socket state guarded by the socket's `state` lock.
struct SocketState {
    /// True until the socket opens, and again once it retires.
    closed: bool,
    transport: SocketTransportState,
    connection_status: SocketConnectionStatus,
    pending_error: Option<SocketError>,
    read_shutdown: bool,
    write_shutdown: bool,
    guest_local_address: Option<SocketAddrV4>,
}

impl SocketState {
    fn kind(&self) -> SocketKind {
        match &self.transport {
            SocketTransportState::Tcp(_) => SocketKind::Tcp,
            SocketTransportState::Udp(_) => SocketKind::Udp,
        }
    }

    fn udp_state(&self) -> BrokerResult<&UdpSocketState> {
        match &self.transport {
            SocketTransportState::Udp(udp) => Ok(udp),
            SocketTransportState::Tcp(_) => Err(BrokerError::Internal),
        }
    }

    fn udp_state_mut(&mut self) -> BrokerResult<&mut UdpSocketState> {
        match &mut self.transport {
            SocketTransportState::Udp(udp) => Ok(udp),
            SocketTransportState::Tcp(_) => Err(BrokerError::Internal),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketKind {
    Tcp,
    Udp,
}

/// A socket whose `state` lock is held.
struct SocketEntry<'a> {
    socket: &'a UserlandSocket,
    state: MutexGuard<'a, SocketState>,
}

impl Deref for SocketEntry<'_> {
    type Target = SocketState;

    fn deref(&self) -> &SocketState {
        &self.state
    }
}

impl DerefMut for SocketEntry<'_> {
    fn deref_mut(&mut self) -> &mut SocketState {
        &mut self.state
    }
}

impl<'a> SocketEntry<'a> {
    fn id(&self) -> u64 {
        self.socket.id
    }

    fn process_authority(&self) -> ProcessId {
        self.socket.process_authority
    }

    fn core(&self) -> &'a ProviderCore {
        &self.socket.core
    }

    fn topology(&self) -> MutexGuard<'a, Topology> {
        lock(&self.socket.core.topology)
    }

    fn inbox(&self) -> InboxGuard<'a> {
        self.socket.inbox.lock()
    }

    /// The readiness this socket derived from its own descriptor and state.
    fn own(&self) -> ReadinessFlags {
        self.inbox().own
    }

    fn drain_inbox(&mut self) -> BrokerResult<()> {
        match self.kind() {
            SocketKind::Tcp => self.drain_guest_reset(),
            SocketKind::Udp => Ok(()),
        }
    }

    /// The host socket an event `token` of this socket refers to.
    fn event_descriptor(&self, token: u64) -> Option<&HostSocket> {
        match &self.transport {
            SocketTransportState::Tcp(tcp) => tcp.descriptor.socket().ok(),
            SocketTransportState::Udp(udp) => udp
                .native_endpoint
                .as_ref()
                .filter(|endpoint| endpoint.event_token == token)
                .map(|endpoint| &endpoint.socket),
        }
    }

    /// Retires the socket; with `failure`, ERROR is its last readiness.
    fn retire(&mut self, failure: bool) {
        if self.closed {
            return;
        }
        self.closed = true;
        {
            let mut inbox = self.inbox();
            if failure {
                inbox.publish_final(ReadinessFlags::ERROR);
            }
            inbox.close();
        }
        match self.kind() {
            SocketKind::Tcp => self.retire_tcp(),
            SocketKind::Udp => self.retire_udp(),
        }
    }

    fn bind_socket(
        &mut self,
        binding: GuestSocketBinding,
    ) -> BrokerResult<SocketOutcome<SocketAddrV4>> {
        let kind = self.kind();
        let already_bound = self.guest_local_address.is_some();
        let binding_kind = if binding.is_tcp() {
            SocketKind::Tcp
        } else {
            SocketKind::Udp
        };
        if !binding.is_valid() || binding_kind != kind {
            return Err(BrokerError::Internal);
        }
        if kind == SocketKind::Udp {
            return self.bind_udp_socket(binding, already_bound);
        }
        self.bind_tcp_socket(binding, already_bound)
    }

    fn send_to_socket(
        &mut self,
        data: RawParts<'_>,
        destination: Option<SocketAddrV4>,
    ) -> BrokerResult<SocketOutcome<usize>> {
        if self.kind() != SocketKind::Udp || data.len() > MAX_UDP_DATAGRAM_SIZE as usize {
            return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
        }
        if let Some(error) = self.take_udp_cached_error() {
            return Ok(SocketOutcome::Failed(error));
        }
        if self.write_shutdown {
            return Ok(SocketOutcome::Failed(SocketError::Shutdown));
        }
        let connected_peer = self.udp_state()?.peer;
        let (peer, authorize_external_reply) = match destination {
            Some(address) => match self.resolve_udp_destination(address) {
                SocketOutcome::Completed(peer) => (peer, connected_peer.is_none()),
                SocketOutcome::Failed(error) => return Ok(SocketOutcome::Failed(error)),
            },
            None => match connected_peer {
                Some(peer) => (peer, false),
                None => return Ok(SocketOutcome::Failed(SocketError::NotConnected)),
            },
        };
        match peer {
            UdpPeer::Internal(destination) => self.send_internal_udp(destination, data),
            UdpPeer::External(destination) => {
                self.send_to_external_udp(data, destination, authorize_external_reply)
            }
        }
    }

    fn shutdown_socket(&mut self, mode: ShutdownMode) -> BrokerResult<SocketOutcome<()>> {
        if self.kind() == SocketKind::Tcp {
            return self.shutdown_tcp_socket(mode);
        }
        let (shut_read, shut_write) = match mode {
            ShutdownMode::Read => (true, false),
            ShutdownMode::Write => (false, true),
            ShutdownMode::Both => (true, true),
            ShutdownMode::Abort | ShutdownMode::StopListening => {
                return Ok(SocketOutcome::Failed(SocketError::InvalidArgument));
            }
            _ => return Err(BrokerError::UnsupportedOperation),
        };
        if shut_read {
            let peer = self.udp_state()?.peer;
            self.filter_udp_receive_queue(peer, true);
        }
        self.read_shutdown |= shut_read;
        self.write_shutdown |= shut_write;
        if shut_read && let Some(endpoint) = self.udp_state_mut()?.native_endpoint.as_mut() {
            endpoint.readable = false;
        }
        if shut_read {
            // Queue discard and shutdown state are already committed.
            let _ = self.rearm_udp_endpoint_if_needed();
        }
        // Shutdown is already committed; ignore a failure to recompute
        // readiness.
        let _ = self.publish_udp_readiness();
        Ok(SocketOutcome::Completed(()))
    }

    fn receive_from_socket(
        &mut self,
        output: RawParts<'_>,
        flags: ReceiveFromFlags,
    ) -> BrokerResult<ReceiveFromOutcome> {
        if let Some(error) = self.take_udp_cached_error() {
            return Ok(ReceiveFromOutcome::Failed(error));
        }
        if self.read_shutdown {
            return Ok(ReceiveFromOutcome::Failed(SocketError::NotConnected));
        }
        let pinned = self.udp_state()?.peeked_origin;
        let next = self.udp_state()?.next_receive_origin;
        let first = pinned.unwrap_or(next);
        let second = match first {
            UdpReceiveOrigin::Internal => UdpReceiveOrigin::External,
            UdpReceiveOrigin::External => UdpReceiveOrigin::Internal,
        };
        for origin in [first, second] {
            let outcome = match origin {
                UdpReceiveOrigin::Internal => self.receive_internal_udp(output, flags)?,
                UdpReceiveOrigin::External => self.receive_external_udp(output, flags)?,
            };
            if let Some(outcome) = outcome {
                return Ok(outcome);
            }
            if pinned.is_some() {
                break;
            }
        }
        self.publish_udp_readiness()?;
        Err(BrokerError::WouldBlock)
    }
}

/// The part of a socket that other sockets may post to without holding its
/// `state`.
struct SocketInbox {
    /// Last published readiness, readable without a lock.
    snapshot: AtomicU32,
    inner: Mutex<InboxState>,
}

/// Readiness inputs and cross-socket deliveries for one socket.
struct InboxState {
    registration: ReadinessRegistration,
    /// Readiness derived from the socket's own descriptor and state.
    own: ReadinessFlags,
    /// A listener's connection queue is non-empty.
    queue_ready: bool,
    /// The guest peer of an internal TCP endpoint reset the connection; the
    /// socket's next call or event applies it.
    reset_posted: bool,
    /// The socket retired: nothing is delivered or published.
    closed: bool,
    udp: UdpInbox,
}

/// A locked inbox.
struct InboxGuard<'a> {
    snapshot: &'a AtomicU32,
    inbox: MutexGuard<'a, InboxState>,
}

impl SocketInbox {
    fn new(registration: ReadinessRegistration) -> Self {
        Self {
            snapshot: AtomicU32::new(0),
            inner: Mutex::new(InboxState {
                registration,
                own: ReadinessFlags::default(),
                queue_ready: false,
                reset_posted: false,
                closed: false,
                udp: UdpInbox::default(),
            }),
        }
    }

    fn lock(&self) -> InboxGuard<'_> {
        InboxGuard {
            snapshot: &self.snapshot,
            inbox: lock(&self.inner),
        }
    }

    fn readiness(&self) -> ReadinessFlags {
        ReadinessFlags(self.snapshot.load(Ordering::Relaxed))
    }
}

impl InboxState {
    fn value(&self) -> ReadinessFlags {
        let mut readiness = self.own;
        if self.queue_ready || self.udp.has_queued_datagrams() {
            readiness = readiness | ReadinessFlags::READ;
        }
        if self.reset_posted {
            readiness = readiness
                | ReadinessFlags::READ
                | ReadinessFlags::ERROR
                | ReadinessFlags::HANGUP
                | ReadinessFlags::CLOSED;
        }
        readiness
    }
}

impl Deref for InboxGuard<'_> {
    type Target = InboxState;

    fn deref(&self) -> &InboxState {
        &self.inbox
    }
}

impl DerefMut for InboxGuard<'_> {
    fn deref_mut(&mut self) -> &mut InboxState {
        &mut self.inbox
    }
}

impl InboxGuard<'_> {
    /// Publishes the combined readiness if it changed.
    fn publish(&mut self) {
        if self.closed {
            return;
        }
        let readiness = self.value();
        if ReadinessFlags(self.snapshot.swap(readiness.0, Ordering::Relaxed)) != readiness {
            self.registration.publish(readiness);
        }
    }

    /// Publishes the combined readiness and wakes waiters even if unchanged.
    fn republish(&mut self) {
        if self.closed {
            return;
        }
        let readiness = self.value();
        if ReadinessFlags(self.snapshot.swap(readiness.0, Ordering::Relaxed)) == readiness {
            self.registration.republish(readiness);
        } else {
            self.registration.publish(readiness);
        }
    }

    fn set_own(&mut self, readiness: ReadinessFlags) {
        self.own = readiness;
        self.publish();
    }

    /// Publishes `readiness` as the socket's last readiness.
    fn publish_final(&mut self, readiness: ReadinessFlags) {
        if self.closed {
            return;
        }
        self.own = readiness;
        self.snapshot.store(readiness.0, Ordering::Relaxed);
        self.registration.publish(readiness);
    }

    /// Stops deliveries and publications, dropping queued datagrams.
    fn close(&mut self) {
        self.closed = true;
        self.udp.clear();
    }
}

fn zeroed_vec(length: usize) -> BrokerResult<Vec<u8>> {
    let mut data = Vec::new();
    data.try_reserve_exact(length)
        .map_err(|_| BrokerError::OutOfMemory)?;
    data.resize(length, 0);
    Ok(data)
}

fn take_socket_error(socket: &SocketEntry<'_>) -> BrokerResult<Option<SocketError>> {
    let tcp = socket.tcp_state()?;
    if !tcp.descriptor.is_external() {
        return Ok(None);
    }
    let external_socket = tcp.descriptor.socket()?;
    match external_socket.take_error() {
        Ok(error) => Ok(error.map(socket_error_from_errno)),
        Err(error) => Err(broker_error_from_errno(error)),
    }
}

fn local_socket_address(socket: &HostSocket) -> BrokerResult<SocketAddrV4> {
    socket.local_address().map_err(broker_error_from_errno)
}

fn status_tcp_socket(socket: &mut SocketEntry<'_>) -> BrokerResult<PlatformSocketStatus> {
    // A connection's failure is reported once, after which the host socket's
    // error is no longer the guest's.
    let query_socket_error = socket.connection_status == SocketConnectionStatus::Connected
        && socket.own().contains(ReadinessFlags::ERROR)
        && !socket.tcp_state()?.connection_failed;
    if query_socket_error && let Some(error) = take_socket_error(socket)? {
        let tcp = socket.tcp_state_mut()?;
        tcp.connection_failed = true;
        tcp.pending_errors.append(TcpPendingError::Socket(error));
    }
    let pending_guest_reset = guest_reset_pending(socket)?;
    let status = socket.connection_status;
    let local_address = socket.guest_local_address;
    if pending_guest_reset && !socket.tcp_state()?.pending_errors.contains_guest_reset() {
        socket
            .tcp_state_mut()?
            .pending_errors
            .append(TcpPendingError::GuestReset);
    }
    let pending_error = socket.tcp_state_mut()?.pending_errors.take();
    let mut readiness = socket.own();
    if pending_error.is_some() && socket.tcp_state()?.pending_errors.is_empty() {
        readiness = ReadinessFlags(readiness.0 & !ReadinessFlags::ERROR.0);
        socket.inbox().own = readiness;
    }
    let response = PlatformSocketStatus {
        status,
        local_address,
        pending_error: pending_error.map(TcpPendingError::error),
    };
    let republish_error = !socket.tcp_state()?.pending_errors.is_empty();
    if pending_guest_reset
        && matches!(pending_error, Some(TcpPendingError::GuestReset))
        && !consume_pending_guest_reset(socket, false)?
    {
        return Err(BrokerError::Internal);
    }
    if republish_error {
        socket.inbox().republish();
    } else if response.pending_error.is_some() {
        socket.inbox().publish();
    }
    Ok(response)
}

const fn socket_kind(request: CreateSocketRequest) -> Option<SocketKind> {
    match (
        request.address_family,
        request.socket_type,
        request.protocol,
    ) {
        (AddressFamily::Ipv4, SocketType::Stream, IpProtocol::Tcp) => Some(SocketKind::Tcp),
        (AddressFamily::Ipv4, SocketType::Datagram, IpProtocol::Udp) => Some(SocketKind::Udp),
        _ => None,
    }
}

fn status_socket(socket: &mut SocketEntry<'_>) -> BrokerResult<PlatformSocketStatus> {
    match socket.kind() {
        SocketKind::Udp => socket.status_udp_socket(),
        SocketKind::Tcp => status_tcp_socket(socket),
    }
}

/// Sets the socket's own readiness, publishing if the combined value changed.
fn set_own_readiness(socket: &SocketEntry<'_>, readiness: ReadinessFlags) {
    socket.inbox().set_own(readiness);
}

/// Sets the socket's own readiness and wakes waiters even if unchanged.
fn republish_own_readiness(socket: &SocketEntry<'_>, readiness: ReadinessFlags) {
    let mut inbox = socket.inbox();
    inbox.own = readiness;
    inbox.republish();
}

const fn can_consume_synchronous_error(status: SocketConnectionStatus) -> bool {
    matches!(status, SocketConnectionStatus::Connected)
}

/// Maps a host error to the broker's [`SocketError`]. Both hosts name their
/// errors after POSIX's, so one mapping serves both. [`Errno::PIPE`], which
/// only a send reports, means that the stream can no longer send.
const fn socket_error_from_errno(error: Errno) -> SocketError {
    match error {
        Errno::CONNREFUSED => SocketError::ConnectionRefused,
        Errno::CONNRESET => SocketError::ConnectionReset,
        Errno::CONNABORTED => SocketError::ConnectionAborted,
        Errno::NETUNREACH => SocketError::NetworkUnreachable,
        Errno::HOSTUNREACH => SocketError::HostUnreachable,
        Errno::TIMEDOUT => SocketError::TimedOut,
        Errno::ADDRINUSE => SocketError::AddressInUse,
        Errno::ADDRNOTAVAIL => SocketError::AddressNotAvailable,
        Errno::NOTCONN | Errno::PIPE => SocketError::NotConnected,
        Errno::INVAL => SocketError::InvalidArgument,
        _ => SocketError::Other,
    }
}

const fn socket_operation_error_from_errno(error: Errno) -> BrokerResult<SocketError> {
    match broker_resource_error_from_errno(error) {
        Some(error) => Err(error),
        None => Ok(socket_error_from_errno(error)),
    }
}

const fn broker_error_from_errno(error: Errno) -> BrokerError {
    match broker_resource_error_from_errno(error) {
        Some(error) => error,
        None => BrokerError::Internal,
    }
}

#[cfg(test)]
impl ProviderCore {
    fn process_state_count(&self) -> usize {
        lock(&self.topology).processes.len()
    }

    /// Runs `hook` at every [`HookPoint`], replacing any previous hook.
    fn set_hook(&self, hook: Option<Hook>) {
        *write_lock(&self.hook) = hook;
    }

    /// The IDs of the live sockets in creation order.
    fn socket_ids(&self) -> Vec<u64> {
        let mut ids: Vec<_> = read_lock(&self.registry).sockets.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Whether every live socket's readiness reflects its state: the
    /// published readiness is current, and TCP data queued for the socket is
    /// readable.
    fn readiness_is_settled(&self) -> bool {
        let sockets: Vec<_> = read_lock(&self.registry)
            .sockets
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        sockets.iter().all(|socket| {
            socket
                .call(|socket| {
                    let queued = socket
                        .tcp_state()
                        .and_then(|tcp| tcp.descriptor.queued_bytes())
                        .is_ok_and(|queued| queued > 0);
                    let inbox = socket.inbox();
                    let published = ReadinessFlags(inbox.snapshot.load(Ordering::Relaxed));
                    Ok(published == inbox.value()
                        && (!queued || published.contains(ReadinessFlags::READ)))
                })
                .unwrap_or(true)
        })
    }
}

#[cfg(test)]
mod tests;
