// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Published TCP ports: host listeners whose clients reach guest listeners.
//!
//! The provider listens on each fixed published host address from its start
//! until it drops. With a published listener IP, it also listens on that IP
//! and the port of each guest listener covering the guest address, for as
//! long as the guest listens. The event thread accepts each host client and
//! queues its connection on the guest listener covering the published guest
//! address, as an external connection with a gateway peer. With no such
//! listener, it accepts and resets the client, which learns at its first read
//! that the guest is not serving. While the guest listener has no room (see
//! `published_room`), the host listener stops accepting, so clients wait in
//! its own backlog, as they would in a full Linux backlog; the next change
//! under `topology` that eases its shortage wakes it, through the topology's
//! [`PublishedWaker`].
//!
//! Each listener is watched for one read event at a time, under a token with
//! [`PUBLISHED_EVENT_TOKEN_FLAG`] and a number that no other listener had, so
//! an event for a listener that closed finds none. An event accepts at most
//! [`MAX_ACCEPTS_PER_EVENT`] clients, then watches again, so one busy port
//! cannot starve other sockets. An accept or a re-watch that fails other
//! than for one connection leaves the listener unwatched for
//! [`FAILURE_RETRY`], rather than spin, and is reported once until an accept
//! or a re-watch succeeds.
//!
//! A guest listener's publication follows the guest's bindings: each change
//! to whether a guest listener covers a port is followed by a check of that
//! port, under the `sync` lock, which opens or closes the port's host
//! listener to match. The last check after a change sees it, so the host
//! listeners end up matching the guest's.
//!
//! Locks: `sync` is taken with no provider lock held, other than a socket's
//! own `state`. A listener's lock is taken by the event thread, by a check,
//! and by the provider's start and drop, never while holding `topology`,
//! which may be taken under it. `table` may be taken under `topology` or a
//! listener's lock, and only the posted-token lock is taken under `table`.

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::socket::{GUEST_IPV4_ADDRESS, GatewayPeerPorts, PublishedTcpPort};

use super::host::{
    Errno, HostErrno as _, HostPoller as _, HostSocket as _, Interest, Network, Poller, Socket,
};
use super::tcp::{PublishedRoom, RoomShortage, reset_host_connection};
use super::{HookPoint, PostedEvents, ProviderCore, lock};

/// Flag of the event tokens of published host listeners; the rest of a
/// token is the listener's number. Socket IDs stay below it.
pub(super) const PUBLISHED_EVENT_TOKEN_FLAG: u64 = 1 << 62;

/// Host clients' connections queued on guest listeners, broker-wide. A
/// guest listener with none queued may still queue one past it.
pub(super) const MAX_QUEUED_PUBLISHED_CONNECTIONS: usize = 128;

/// Host clients accepted per event of one listener.
pub(super) const MAX_ACCEPTS_PER_EVENT: usize = 64;

/// How long a listener goes unwatched after an accept or a re-watch failed
/// other than for one connection, or memory ran short for its resumption.
const FAILURE_RETRY: Duration = Duration::from_millis(100);

/// How a listener is watched: for one read event, its next client.
const LISTENER_INTEREST: Interest = Interest::Oneshot {
    read: true,
    write: false,
};

/// How soon a listener waiting for room checks again should no wake reach
/// it. Every change that eases its shortage wakes it, so this only bounds
/// the cost of one that is missed.
const ROOM_RETRY: Duration = Duration::from_secs(1);

/// Pending connections each host listener holds before the event thread
/// accepts them.
const HOST_LISTEN_BACKLOG: u32 = 128;

/// The provider's published host listeners.
pub(super) struct PublishedPorts {
    table: Arc<Mutex<PublishedTable>>,
    /// The host IP that guest listeners' ports are published on, if any.
    listener_ip: Option<Ipv4Addr>,
    /// Serializes the checks of guest listeners' publications, and holds
    /// whether one failed, with none succeeding since, so that a guest whose
    /// listens keep failing to publish is reported once.
    sync: Mutex<bool>,
    /// Peers of published connections, from queueing until their sockets
    /// close.
    gateway_ports: GatewayPeerPorts,
    /// How many of the next accepts fail, for tests.
    #[cfg(test)]
    failing_accepts: AtomicUsize,
}

/// Wakes the published listeners waiting for room. The topology holds it,
/// so that each change under `topology` that eases a shortage wakes them.
pub(super) struct PublishedWaker {
    table: Arc<Mutex<PublishedTable>>,
    posted: Arc<PostedEvents>,
}

impl PublishedWaker {
    /// Posts a wake for each listener waiting for `shortage` to ease, so it
    /// checks again.
    pub(super) fn wake(&self, shortage: RoomShortage) {
        let table = lock(&self.table);
        for (token, pause) in &table.paused {
            if matches!(pause, Pause::NoRoom(_, waited) if *waited == shortage) {
                self.posted.post(*token);
            }
        }
    }
}

/// Listeners whose pause ended, gathered under the `table` lock and resumed
/// after it. The event thread keeps one, so it reuses its room.
#[derive(Default)]
pub(super) struct DueListeners(Vec<(u64, Arc<PublishedListener>)>);

/// The live published listeners.
struct PublishedTable {
    /// Listeners by event token.
    listeners: HashMap<u64, Arc<PublishedListener>>,
    /// Tokens of the listeners that publish guest listeners, by guest port.
    guest_listeners: HashMap<u16, u64>,
    /// The pauses of the unwatched live listeners, by event token. Its room
    /// is reserved along with `listeners`', so pausing cannot fail.
    paused: HashMap<u64, Pause>,
    /// No pause in `paused` ends before this. A pause that a wake or a
    /// close removed may leave it early, which costs one needless scan.
    earliest_pause_end: Option<Instant>,
    /// The next listener's number.
    next: u64,
}

impl PublishedTable {
    /// Adds `listener`, returning its token, or gives it back if event
    /// tokens or memory ran out. With `guest_listener`, it publishes that
    /// guest listener.
    fn insert(
        &mut self,
        listener: Arc<PublishedListener>,
        guest_listener: bool,
    ) -> Result<u64, Arc<PublishedListener>> {
        let paused_room = (self.listeners.len() + 1).saturating_sub(self.paused.len());
        if self.next >= PUBLISHED_EVENT_TOKEN_FLAG
            || self.listeners.try_reserve(1).is_err()
            || self.paused.try_reserve(paused_room).is_err()
            || (guest_listener && self.guest_listeners.try_reserve(1).is_err())
        {
            return Err(listener);
        }
        let token = PUBLISHED_EVENT_TOKEN_FLAG | self.next;
        self.next += 1;
        if guest_listener {
            self.guest_listeners
                .insert(listener.mapping.guest_port, token);
        }
        self.listeners.insert(token, listener);
        Ok(token)
    }

    /// Removes the listener with `token`, with its pause.
    fn remove(&mut self, token: u64) -> Option<Arc<PublishedListener>> {
        self.paused.remove(&token);
        self.listeners.remove(&token)
    }
}

struct PublishedListener {
    mapping: PublishedTcpPort,
    state: Mutex<ListenerState>,
}

impl PublishedListener {
    fn new(network: Network, mapping: PublishedTcpPort) -> Result<Self, Errno> {
        Ok(Self {
            mapping,
            state: Mutex::new(ListenerState {
                socket: Socket::tcp_listener(network, mapping.host_address, HOST_LISTEN_BACKLOG)?,
                closed: false,
                failing: false,
                refusing: false,
            }),
        })
    }

    /// Marks the listener, which has left the table, closed and stops
    /// watching it, so that an event already taken for it finds it closed.
    /// Its socket closes with the last reference.
    fn retire(&self, poller: &Poller) {
        let mut state = lock(&self.state);
        state.closed = true;
        poller.delete(&mut state.socket);
    }
}

struct ListenerState {
    socket: Socket,
    /// The listener left the table and is no longer watched.
    closed: bool,
    /// A failure to accept or watch was reported, and no accept or re-watch
    /// succeeded since, so that a lasting failure is reported once.
    failing: bool,
    /// A client was reset for lack of resources, and none was queued since,
    /// so that a lasting shortage is reported once.
    refusing: bool,
}

#[derive(Clone, Copy)]
enum Pause {
    /// An accept or a re-watch failed; nothing resumes the listener before
    /// the time.
    Failed(Instant),
    /// The guest listener had no room for the shortage; a wake when it
    /// eases, or the time, resumes the listener.
    NoRoom(Instant, RoomShortage),
}

impl Pause {
    fn until(self) -> Instant {
        match self {
            Self::Failed(until) | Self::NoRoom(until, _) => until,
        }
    }
}

impl PublishedPorts {
    /// Listens in `network` on each mapping's host address, failing if one
    /// is taken, and publishes guest listeners on `listener_ip` once they
    /// listen.
    pub(super) fn bind(
        network: Network,
        mappings: &[PublishedTcpPort],
        listener_ip: Option<Ipv4Addr>,
    ) -> IoResult<Self> {
        let mut table = PublishedTable {
            listeners: HashMap::new(),
            guest_listeners: HashMap::new(),
            paused: HashMap::new(),
            earliest_pause_end: None,
            next: 0,
        };
        for mapping in mappings {
            let listener = PublishedListener::new(network, *mapping).map_err(|error| {
                error.with_context(format_args!(
                    "cannot publish guest TCP port {} on {}",
                    mapping.guest_port, mapping.host_address
                ))
            })?;
            // Tokens cannot run out for a command line's mappings.
            table
                .insert(Arc::new(listener), false)
                .map_err(|_| Error::from(ErrorKind::OutOfMemory))?;
        }
        Ok(Self {
            table: Arc::new(Mutex::new(table)),
            listener_ip,
            sync: Mutex::new(false),
            gateway_ports: GatewayPeerPorts::new(),
            #[cfg(test)]
            failing_accepts: AtomicUsize::new(0),
        })
    }

    /// Returns a waker for the listeners waiting for room, which posts their
    /// wakes to `posted`.
    pub(super) fn waker(&self, posted: &Arc<PostedEvents>) -> PublishedWaker {
        PublishedWaker {
            table: Arc::clone(&self.table),
            posted: Arc::clone(posted),
        }
    }

    /// Returns how many listeners there may be at once, with at most
    /// `max_sockets` guest listeners.
    pub(super) fn max_listeners(&self, max_sockets: usize) -> usize {
        let fixed = lock(&self.table).listeners.len();
        if self.listener_ip.is_some() {
            fixed.saturating_add(max_sockets)
        } else {
            fixed
        }
    }

    /// Returns the live listeners, or none if memory is short.
    fn listeners(&self) -> Option<Vec<(u64, Arc<PublishedListener>)>> {
        let table = lock(&self.table);
        let mut listeners = Vec::new();
        listeners.try_reserve_exact(table.listeners.len()).ok()?;
        listeners.extend(
            table
                .listeners
                .iter()
                .map(|(token, listener)| (*token, Arc::clone(listener))),
        );
        Some(listeners)
    }
}

impl ProviderCore {
    /// Watches every fixed published listener, once the provider is shared
    /// with the event thread.
    pub(super) fn watch_published(&self) -> IoResult<()> {
        for (token, listener) in self
            .published
            .listeners()
            .ok_or_else(|| Error::from(ErrorKind::OutOfMemory))?
        {
            self.watch_published_listener(&mut lock(&listener.state), token)
                .map_err(|error| {
                    error.with_context(format_args!(
                        "cannot watch guest TCP port {} published on {}",
                        listener.mapping.guest_port, listener.mapping.host_address
                    ))
                })?;
        }
        Ok(())
    }

    fn watch_published_listener(&self, state: &mut ListenerState, token: u64) -> Result<(), Errno> {
        self.poller.add(&mut state.socket, token, LISTENER_INTEREST)
    }

    /// Stops watching every published listener before they close.
    pub(super) fn unwatch_published(&mut self) {
        // Out of the table, they are retired without holding its lock,
        // which the event thread takes under theirs.
        let listeners = core::mem::take(&mut lock(&self.published.table).listeners);
        for listener in listeners.values() {
            listener.retire(&self.poller);
        }
    }

    /// Makes the publication of `guest_port` on the published listener IP,
    /// if there is one, match the guest: opens a host listener if a guest
    /// listener covers the guest address and the port, or closes it if none
    /// does; see the module docs. Call it, holding no provider lock but a
    /// socket's own, after each change to whether a guest listener covers
    /// the port.
    pub(super) fn sync_guest_listener_publication(&self, guest_port: u16) {
        let Some(ip) = self.published.listener_ip else {
            return;
        };
        let mut failing = lock(&self.published.sync);
        let listening = lock(&self.topology)
            .tcp
            .listener_covers(SocketAddrV4::new(GUEST_IPV4_ADDRESS, guest_port));
        let published = lock(&self.published.table)
            .guest_listeners
            .get(&guest_port)
            .copied();
        let published = match (listening, published) {
            (true, None) => self.open_listener_publication(
                PublishedTcpPort {
                    host_address: SocketAddrV4::new(ip, guest_port),
                    guest_port,
                },
                &mut failing,
            ),
            (false, Some(token)) => {
                self.close_listener_publication(guest_port, token);
                false
            }
            (_, published) => published.is_some(),
        };
        self.hook(HookPoint::ListenerPublished {
            guest_port,
            published,
        });
    }

    /// Opens and watches a host listener publishing a guest listener as
    /// `mapping`, reporting whether it did. A failure leaves the port
    /// unpublished, as the guest's listener works without it, and is
    /// reported unless `failing` says one was since the last success.
    fn open_listener_publication(&self, mapping: PublishedTcpPort, failing: &mut bool) -> bool {
        let mut failed = |error: &dyn std::fmt::Display| {
            if !core::mem::replace(failing, true) {
                std::eprintln!(
                    "cannot publish the guest TCP listener on port {} at {}, nor report \
                     further failures until one succeeds: {error}",
                    mapping.guest_port,
                    mapping.host_address
                );
            }
            false
        };
        let listener = match PublishedListener::new(self.network, mapping) {
            Ok(listener) => Arc::new(listener),
            Err(error) => return failed(&error),
        };
        let Ok(token) = lock(&self.published.table).insert(Arc::clone(&listener), true) else {
            return failed(&"out of memory or event tokens");
        };
        // The event thread finds the listener once it is in the table.
        let watched = self.watch_published_listener(&mut lock(&listener.state), token);
        if let Err(error) = watched {
            self.close_listener_publication(mapping.guest_port, token);
            return failed(&error);
        }
        *failing = false;
        true
    }

    /// Closes the host listener with `token` that publishes the guest
    /// listener on `guest_port`. Clients waiting in its backlog are reset.
    ///
    /// Only the topology's [`PublishedWaker`] posts the token, from the
    /// table, so once the listener leaves the table no new post can arrive,
    /// and a pending one can be cancelled.
    fn close_listener_publication(&self, guest_port: u16, token: u64) {
        let listener = {
            let mut table = lock(&self.published.table);
            table.guest_listeners.remove(&guest_port);
            table.remove(token)
        };
        self.posted.cancel(token);
        if let Some(listener) = listener {
            listener.retire(&self.poller);
        }
    }

    /// Accepts the clients of the published listener with event `token`,
    /// unless it closed or a failure paused it. The event is a host event,
    /// or a wake from the topology's [`PublishedWaker`].
    pub(super) fn handle_published_event(&self, token: u64) {
        let listener = {
            let mut table = lock(&self.published.table);
            match table.paused.get(&token).copied() {
                Some(Pause::Failed(_)) => return,
                Some(Pause::NoRoom(..)) => {
                    table.paused.remove(&token);
                }
                None => {}
            }
            let Some(listener) = table.listeners.get(&token) else {
                return;
            };
            Arc::clone(listener)
        };
        let mut state = lock(&listener.state);
        if state.closed {
            return;
        }
        self.accept_published(&listener, &mut state, token);
    }

    /// Accepts and delivers clients while the guest has room, then watches
    /// the listener again; or pauses it, unwatched.
    fn accept_published(
        &self,
        listener: &PublishedListener,
        state: &mut ListenerState,
        token: u64,
    ) {
        let guest_address = listener.mapping.guest_address();
        for _ in 0..MAX_ACCEPTS_PER_EVENT {
            // The check, the accept, and the queueing are one step, so the
            // room cannot fill between them.
            let mut topology = lock(&self.topology);
            let covering_listener = match topology.published_room(guest_address, self.max_sockets) {
                PublishedRoom::Available(listener_id) => Some(listener_id),
                PublishedRoom::NoListener => None,
                PublishedRoom::Full(shortage) => {
                    topology.tcp.note_published_waiting(shortage);
                    self.pause_published(
                        token,
                        Pause::NoRoom(Instant::now() + ROOM_RETRY, shortage),
                    );
                    return;
                }
            };
            let socket = match self.published.accept(&state.socket) {
                Ok(socket) => socket,
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR | Errno::CONNABORTED) => continue,
                Err(error) => {
                    drop(topology);
                    self.back_off_published(listener, state, token, "accept", error);
                    return;
                }
            };
            state.failing = false;
            // A client with no listener to reach is reset without an error.
            let refused = match covering_listener {
                Some(listener_id) => topology
                    .queue_published_connection(
                        listener_id,
                        guest_address,
                        socket,
                        &self.published.gateway_ports,
                    )
                    .err()
                    .map(|(socket, error)| (socket, Some(error))),
                None => Some((socket, None)),
            };
            drop(topology);
            let queued = match refused {
                None => {
                    state.refusing = false;
                    true
                }
                Some((socket, error)) => {
                    if let Some(error) = error
                        && !core::mem::replace(&mut state.refusing, true)
                    {
                        std::eprintln!(
                            "cannot queue clients of the guest TCP port {} published at {}, \
                             resetting them: {error:?}",
                            listener.mapping.guest_port,
                            listener.mapping.host_address
                        );
                    }
                    reset_host_connection(socket);
                    false
                }
            };
            self.hook(HookPoint::PublishedClient {
                guest_port: listener.mapping.guest_port,
                queued,
            });
        }
        self.rearm_published(listener, state, token);
    }

    /// Leaves the listener with `token` unwatched until `pause` ends, unless
    /// it closed meanwhile.
    fn pause_published(&self, token: u64, pause: Pause) {
        let mut table = lock(&self.published.table);
        if table.listeners.contains_key(&token) {
            // Cannot allocate: `paused` has room for every live listener.
            table.paused.insert(token, pause);
            table.earliest_pause_end = Some(
                table
                    .earliest_pause_end
                    .map_or(pause.until(), |earliest| earliest.min(pause.until())),
            );
        }
    }

    /// Pauses a listener whose `operation` failed with `error` for
    /// [`FAILURE_RETRY`], reporting the first failure since its last success.
    fn back_off_published(
        &self,
        listener: &PublishedListener,
        state: &mut ListenerState,
        token: u64,
        operation: &str,
        error: Errno,
    ) {
        if !state.failing {
            state.failing = true;
            std::eprintln!(
                "cannot {operation} clients of the guest TCP port {} published at {}, \
                 retrying: {error}",
                listener.mapping.guest_port,
                listener.mapping.host_address
            );
        }
        self.hook(HookPoint::PublishedBackOff {
            guest_port: listener.mapping.guest_port,
        });
        self.pause_published(token, Pause::Failed(Instant::now() + FAILURE_RETRY));
    }

    fn rearm_published(&self, listener: &PublishedListener, state: &mut ListenerState, token: u64) {
        match self
            .poller
            .modify(&mut state.socket, token, LISTENER_INTEREST)
        {
            Ok(()) => state.failing = false,
            Err(error) => self.back_off_published(listener, state, token, "watch for", error),
        }
    }

    /// Resumes each paused listener whose pause ended, gathering them in
    /// `due`, and returns when the next pause ends, or a little before, if
    /// any is left.
    ///
    /// Only the event thread pauses listeners, so the time it returns covers
    /// every pause until the thread's next call.
    pub(super) fn resume_published(&self, due: &mut DueListeners) -> Option<Instant> {
        let now = Instant::now();
        {
            let mut table = lock(&self.published.table);
            if table.paused.is_empty() {
                table.earliest_pause_end = None;
                return None;
            }
            if let Some(earliest) = table.earliest_pause_end
                && earliest > now
            {
                return Some(earliest);
            }
            let PublishedTable {
                listeners, paused, ..
            } = &mut *table;
            paused.retain(|token, pause| {
                if pause.until() > now {
                    return true;
                }
                let Some(listener) = listeners.get(token) else {
                    return false;
                };
                // Short of memory, the listener waits for a later call
                // rather than leave its ended pause to spin the event thread.
                if due.0.try_reserve(1).is_err() {
                    *pause = Pause::Failed(now + FAILURE_RETRY);
                    return true;
                }
                due.0.push((*token, Arc::clone(listener)));
                false
            });
        }
        // A resumed listener that pauses again ends its pause after `now`.
        for (token, listener) in due.0.drain(..) {
            let mut state = lock(&listener.state);
            if !state.closed {
                self.accept_published(&listener, &mut state, token);
            }
        }
        let mut table = lock(&self.published.table);
        table.earliest_pause_end = table.paused.values().map(|pause| pause.until()).min();
        table.earliest_pause_end
    }
}

impl PublishedPorts {
    /// Accepts a client of `socket`, unless a test made the accept fail.
    #[cfg_attr(
        not(test),
        expect(clippy::unused_self, reason = "only tests fail accepts")
    )]
    fn accept(&self, socket: &Socket) -> Result<Socket, Errno> {
        #[cfg(test)]
        if self
            .failing_accepts
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_sub(1)
            })
            .is_ok()
        {
            return Err(Errno::INVAL);
        }
        socket.accept()
    }
}

#[cfg(test)]
impl ProviderCore {
    /// The host address of the fixed published listener at `index`.
    pub(super) fn published_host_address(&self, index: u64) -> SocketAddrV4 {
        let listener = Arc::clone(
            &lock(&self.published.table).listeners[&(PUBLISHED_EVENT_TOKEN_FLAG | index)],
        );
        lock(&listener.state).socket.local_address().unwrap()
    }

    /// How many gateway peer ports are leased.
    pub(super) fn gateway_peer_count(&self) -> usize {
        self.published.gateway_ports.leased_count()
    }

    /// How many guest listeners are published.
    pub(super) fn published_guest_listener_count(&self) -> usize {
        lock(&self.published.table).guest_listeners.len()
    }

    /// The event token of the listener publishing the guest listener on
    /// `guest_port`.
    pub(super) fn published_guest_listener_token(&self, guest_port: u16) -> Option<u64> {
        lock(&self.published.table)
            .guest_listeners
            .get(&guest_port)
            .copied()
    }

    /// The shortage the listener with `token` waits for to ease, if it
    /// waits for room.
    pub(super) fn published_shortage(&self, token: u64) -> Option<RoomShortage> {
        match lock(&self.published.table).paused.get(&token) {
            Some(Pause::NoRoom(_, shortage)) => Some(*shortage),
            _ => None,
        }
    }

    /// Whether an event for `token` is posted and not yet taken.
    pub(super) fn posted_holds(&self, token: u64) -> bool {
        lock(&self.posted.tokens).contains(&token)
    }

    /// Makes the next `count` accepts of published listeners fail.
    pub(super) fn fail_published_accepts(&self, count: usize) {
        self.published
            .failing_accepts
            .store(count, Ordering::Relaxed);
    }

    /// How many of the accepts that [`Self::fail_published_accepts`] armed
    /// have yet to fail.
    pub(super) fn published_accepts_left_to_fail(&self) -> usize {
        self.published.failing_accepts.load(Ordering::Relaxed)
    }
}
