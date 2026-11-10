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
//! that the guest is not serving. While the listener has no room (a full
//! backlog, or no room under [`MAX_QUEUED_PUBLISHED_CONNECTIONS`], which a
//! guest listener with no host client queued may exceed by one so that one
//! stalled listener cannot stop the others, or under the global socket
//! limit), it stops accepting, so clients wait in the host listener's own
//! backlog, as they would in a full Linux backlog; the guest's next accept,
//! or a periodic check, resumes it.
//!
//! Each listener is watched for one read event at a time, under a token with
//! [`PUBLISHED_EVENT_TOKEN_FLAG`] and a number that no other listener had, so
//! an event for a listener that closed finds none. An event accepts at most
//! [`MAX_ACCEPTS_PER_EVENT`] clients, then watches again, so one busy port
//! cannot starve other sockets. An accept that fails other than for one
//! connection leaves the listener unwatched for [`ACCEPT_RETRY`], rather
//! than spin, and is reported once until an accept succeeds.
//!
//! A guest listener's publication follows the guest's bindings: each change
//! to whether a guest listener covers a port is followed by a check of that
//! port, under the `sync` lock, which opens or closes the port's host
//! listener to match. The last check after a change sees it, so the host
//! listeners end up matching the guest's.
//!
//! Locks: `sync` is taken with no provider lock held, other than a socket's
//! own `state`. A listener's lock is taken by the event thread, by a check,
//! and by the provider's drop, never while holding `topology`, which may be
//! taken under it. `table` is a leaf.

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::socket::{GUEST_IPV4_ADDRESS, GatewayPeerPorts, PublishedTcpPort};

use super::host::{
    Errno, HostErrno as _, HostPoller as _, HostSocket as _, Interest, Network, Poller, Socket,
};
use super::tcp::{PublishedRoom, reset_host_connection};
use super::{HookPoint, ProviderCore, lock};

/// Flag of the event tokens of published host listeners; the rest of a
/// token is the listener's number. Socket IDs stay below it.
pub(super) const PUBLISHED_EVENT_TOKEN_FLAG: u64 = 1 << 62;

/// Host clients' connections queued on guest listeners, broker-wide.
pub(super) const MAX_QUEUED_PUBLISHED_CONNECTIONS: usize = 128;

/// Host clients accepted per event of one listener.
pub(super) const MAX_ACCEPTS_PER_EVENT: usize = 64;

/// How long a listener goes unwatched after an accept or a re-watch failed
/// other than for one connection.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// How soon a listener waiting for room checks again, should no accept wake
/// it first: room can also come from a listener closing, or from sockets
/// closing under the global limit.
const ROOM_RETRY: Duration = Duration::from_millis(10);

/// Pending connections each host listener holds before the event thread
/// accepts them.
const HOST_LISTEN_BACKLOG: u32 = 128;

/// The provider's published host listeners.
pub(super) struct PublishedPorts {
    table: Mutex<PublishedTable>,
    /// The host IP that guest listeners' ports are published on, if any.
    listener_ip: Option<Ipv4Addr>,
    /// Serializes the checks of guest listeners' publications.
    sync: Mutex<()>,
    /// Peers of published connections, from queueing until their sockets
    /// close.
    gateway_ports: GatewayPeerPorts,
}

/// The live published listeners.
struct PublishedTable {
    /// Listeners by event token.
    listeners: HashMap<u64, Arc<PublishedListener>>,
    /// Tokens of the listeners that publish guest listeners, by guest port.
    guest_listeners: HashMap<u16, u64>,
    /// The pauses of the unwatched live listeners, by event token. Its room
    /// is reserved along with `listeners`', so pausing cannot fail.
    paused: HashMap<u64, Pause>,
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
            }),
        })
    }

    /// Stops watching the listener, which has left the table, so that an
    /// event already taken for it finds it closed.
    fn close(&self, poller: &Poller) {
        let mut state = lock(&self.state);
        state.closed = true;
        poller.delete(&mut state.socket);
    }
}

struct ListenerState {
    socket: Socket,
    /// The listener left the table and is no longer watched.
    closed: bool,
    /// A failure to accept or watch was reported, and none of its accepts
    /// succeeded since, so that a lasting failure is reported once.
    failing: bool,
}

#[derive(Clone, Copy)]
enum Pause {
    /// An accept or a re-watch failed; nothing resumes the listener before
    /// the time.
    Failed(Instant),
    /// The guest listener had no room; a wake or the time resumes it.
    NoRoom(Instant),
}

impl Pause {
    fn until(self) -> Instant {
        match self {
            Self::Failed(until) | Self::NoRoom(until) => until,
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
            next: 0,
        };
        for mapping in mappings {
            let listener = PublishedListener::new(network, *mapping).map_err(|error| {
                let error = Error::from(error);
                Error::new(
                    error.kind(),
                    format!(
                        "cannot publish guest TCP port {} on {}: {error}",
                        mapping.guest_port, mapping.host_address
                    ),
                )
            })?;
            // Tokens cannot run out for a command line's mappings.
            table
                .insert(Arc::new(listener), false)
                .map_err(|_| Error::from(ErrorKind::OutOfMemory))?;
        }
        Ok(Self {
            table: Mutex::new(table),
            listener_ip,
            sync: Mutex::new(()),
            gateway_ports: GatewayPeerPorts::new(),
        })
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

    /// Returns the listener with event `token`, if it is live.
    fn listener(&self, token: u64) -> Option<Arc<PublishedListener>> {
        lock(&self.table).listeners.get(&token).cloned()
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
                .map_err(Error::from)?;
        }
        Ok(())
    }

    fn watch_published_listener(&self, state: &mut ListenerState, token: u64) -> Result<(), Errno> {
        self.poller.add(
            &mut state.socket,
            token,
            Interest::Oneshot {
                read: true,
                write: false,
            },
        )
    }

    /// Stops watching every published listener before they close.
    pub(super) fn unwatch_published(&mut self) {
        let table = self
            .published
            .table
            .get_mut()
            .expect("socket provider lock poisoned");
        for listener in table.listeners.values() {
            listener.close(&self.poller);
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
        let _sync = lock(&self.published.sync);
        let listening = lock(&self.topology)
            .tcp
            .listener_covers(SocketAddrV4::new(GUEST_IPV4_ADDRESS, guest_port));
        let published = lock(&self.published.table)
            .guest_listeners
            .get(&guest_port)
            .copied();
        let published = match (listening, published) {
            (true, None) => self.open_listener_publication(PublishedTcpPort {
                host_address: SocketAddrV4::new(ip, guest_port),
                guest_port,
            }),
            (false, Some(token)) => {
                self.close_listener_publication(guest_port, token);
                false
            }
            (_, published) => published.is_some(),
        };
        self.hook(HookPoint::ListenerPublished(guest_port, published));
    }

    /// Opens and watches a host listener publishing a guest listener as
    /// `mapping`, reporting whether it did. A failure leaves the port
    /// unpublished, as the guest's listener works without it.
    fn open_listener_publication(&self, mapping: PublishedTcpPort) -> bool {
        let failed = |error: &dyn std::fmt::Display| {
            std::eprintln!(
                "cannot publish the guest TCP listener on port {} at {}: {error}",
                mapping.guest_port,
                mapping.host_address
            );
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
        true
    }

    /// Closes the host listener with `token` that publishes the guest
    /// listener on `guest_port`. Clients waiting in its backlog are reset.
    ///
    /// Only [`Self::wake_published`] posts the token, from the table, so
    /// once the listener leaves the table, cancelling a pending post keeps
    /// stale tokens from filling the posted set as listeners come and go.
    fn close_listener_publication(&self, guest_port: u16, token: u64) {
        let listener = {
            let mut table = lock(&self.published.table);
            table.guest_listeners.remove(&guest_port);
            table.remove(token)
        };
        self.posted.cancel(token);
        if let Some(listener) = listener {
            listener.close(&self.poller);
        }
    }

    /// Accepts the clients of the published listener with event `token`,
    /// unless it closed or an accept failure paused it. The event is a host
    /// event, or a wake from [`Self::wake_published`].
    pub(super) fn handle_published_event(&self, token: u64) {
        let Some(listener) = self.published.listener(token) else {
            return;
        };
        let mut state = lock(&listener.state);
        if state.closed {
            return;
        }
        {
            let mut table = lock(&self.published.table);
            match table.paused.get(&token).copied() {
                Some(Pause::Failed(_)) => return,
                Some(Pause::NoRoom(_)) => {
                    table.paused.remove(&token);
                }
                None => {}
            }
        }
        self.accept_published(&listener, &mut state, token);
    }

    /// Wakes each published listener waiting for room, so it checks for it.
    ///
    /// Posting takes only the `table` leaf and the innermost posted-token
    /// lock, so callers may hold any other lock.
    pub(super) fn wake_published(&self) {
        let table = lock(&self.published.table);
        for (token, pause) in &table.paused {
            if matches!(pause, Pause::NoRoom(_)) {
                self.posted.post(*token);
            }
        }
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
            // room cannot fill between them, and an accept that empties the
            // backlog after a full check sees `published_waiting`.
            let mut topology = lock(&self.topology);
            let room = topology.published_room(guest_address, self.max_sockets);
            if room == PublishedRoom::Full {
                topology.tcp.published_waiting = true;
                drop(topology);
                self.pause_published(token, Pause::NoRoom(Instant::now() + ROOM_RETRY));
                return;
            }
            let rejected = match state.socket.accept() {
                Ok(socket) => {
                    state.failing = false;
                    match room {
                        PublishedRoom::Available(listener_id) => topology
                            .queue_published_connection(
                                listener_id,
                                guest_address,
                                socket,
                                &self.published.gateway_ports,
                            )
                            .err(),
                        PublishedRoom::NoListener | PublishedRoom::Full => Some(socket),
                    }
                }
                Err(Errno::AGAIN) => {
                    state.failing = false;
                    break;
                }
                Err(Errno::INTR | Errno::CONNABORTED) => continue,
                Err(error) => {
                    drop(topology);
                    self.fail_published(listener, state, token, "accept", error);
                    return;
                }
            };
            drop(topology);
            let queued = rejected.is_none();
            if let Some(socket) = rejected {
                reset_host_connection(socket);
            }
            self.hook(HookPoint::Published(listener.mapping.guest_port, queued));
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
        }
    }

    /// Pauses a listener whose `operation` failed with `error`, reporting
    /// the first failure since its last success.
    fn fail_published(
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
        self.pause_published(token, Pause::Failed(Instant::now() + ACCEPT_RETRY));
    }

    fn rearm_published(&self, listener: &PublishedListener, state: &mut ListenerState, token: u64) {
        let rearmed = self.poller.modify(
            &mut state.socket,
            token,
            Interest::Oneshot {
                read: true,
                write: false,
            },
        );
        if let Err(error) = rearmed {
            self.fail_published(listener, state, token, "watch for", error);
        }
    }

    /// Resumes each paused listener whose pause ended, and returns when the
    /// next pause ends, if any is left.
    ///
    /// Only the event thread pauses listeners, so the time it returns covers
    /// every pause until the thread's next call.
    pub(super) fn resume_published(&self) -> Option<Instant> {
        let now = Instant::now();
        loop {
            // A resumed listener that pauses again ends its pause after
            // `now`, so each one resumes at most once.
            let resumed = {
                let mut table = lock(&self.published.table);
                let Some(token) = table
                    .paused
                    .iter()
                    .find_map(|(token, pause)| (pause.until() <= now).then_some(*token))
                else {
                    return table.paused.values().map(|pause| pause.until()).min();
                };
                table.paused.remove(&token);
                table
                    .listeners
                    .get(&token)
                    .cloned()
                    .map(|listener| (token, listener))
            };
            let Some((token, listener)) = resumed else {
                continue;
            };
            let mut state = lock(&listener.state);
            if !state.closed {
                self.accept_published(&listener, &mut state, token);
            }
        }
    }
}

#[cfg(test)]
impl ProviderCore {
    /// The host address of the fixed published listener at `index`.
    pub(super) fn published_host_address(&self, index: u64) -> SocketAddrV4 {
        let listener = self
            .published
            .listener(PUBLISHED_EVENT_TOKEN_FLAG | index)
            .unwrap();
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

    /// Whether the listener with `token` waits for room.
    pub(super) fn published_waits_for_room(&self, token: u64) -> bool {
        matches!(
            lock(&self.published.table).paused.get(&token),
            Some(Pause::NoRoom(_))
        )
    }

    /// Whether an event for `token` is posted and not yet taken.
    pub(super) fn posted_holds(&self, token: u64) -> bool {
        lock(&self.posted.tokens).contains(&token)
    }
}
