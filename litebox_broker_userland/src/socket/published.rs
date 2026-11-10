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
//! backlog, or no room under [`MAX_QUEUED_PUBLISHED_CONNECTIONS`] or the
//! global socket limit), it stops accepting, so clients wait in the host
//! listener's own backlog, as they would in a full Linux backlog; the guest's
//! next accept, or a periodic check, resumes it.
//!
//! Each listener is watched for one read event at a time, under a token with
//! [`PUBLISHED_EVENT_TOKEN_FLAG`] and a number that no other listener had, so
//! an event for a listener that closed finds none. An event accepts at most
//! [`MAX_ACCEPTS_PER_EVENT`] clients, then watches again, so one busy port
//! cannot starve other sockets. An accept that fails other than for one
//! connection leaves the listener unwatched for [`ACCEPT_RETRY`], rather
//! than spin.
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
use std::io::{Error, Result as IoResult};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::socket::{GUEST_IPV4_ADDRESS, GatewayPeerPorts, PublishedTcpPort};

use super::host::{
    Errno, HostErrno as _, HostPoller as _, HostSocket as _, Interest, Network, Socket,
};
use super::tcp::{PublishedRoom, reset_host_connection};
use super::{HookPoint, ProviderCore, lock};

/// Flag of the event tokens of published host listeners; the rest of a
/// token is the listener's number. Socket IDs stay below it.
pub(super) const PUBLISHED_EVENT_TOKEN_FLAG: u64 = 1 << 62;

/// Host clients' connections queued on guest listeners, broker-wide.
pub(crate) const MAX_QUEUED_PUBLISHED_CONNECTIONS: usize = 128;

/// Host clients accepted per event of one listener.
pub(super) const MAX_ACCEPTS_PER_EVENT: usize = 64;

/// How long a listener goes unwatched after an accept failed for want of a
/// resource.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// How soon a listener waiting for room checks again, should no accept wake
/// it first: room can also come from a listener closing, or from sockets
/// closing under the global limit. The event thread's idle wait may delay
/// the check further.
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
    pub(super) gateway_ports: GatewayPeerPorts,
    /// Some listener is paused.
    paused: AtomicBool,
}

/// The live published listeners.
struct PublishedTable {
    /// Listeners by event token.
    listeners: HashMap<u64, Arc<PublishedListener>>,
    /// Tokens of the listeners that publish guest listeners, by guest port.
    guest_listeners: HashMap<u16, u64>,
    /// The next listener's number.
    next: u64,
}

impl PublishedTable {
    /// Adds `listener`, returning its token, or gives it back if no token or
    /// memory is left. With `guest_listener`, it publishes that guest
    /// listener.
    fn insert(
        &mut self,
        listener: Arc<PublishedListener>,
        guest_listener: bool,
    ) -> Result<u64, Arc<PublishedListener>> {
        if self.next >= PUBLISHED_EVENT_TOKEN_FLAG
            || self.listeners.try_reserve(1).is_err()
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
                pause: None,
                closed: false,
            }),
        })
    }
}

struct ListenerState {
    socket: Socket,
    /// Why, and until when, the listener is not watched.
    pause: Option<Pause>,
    /// The listener left the table and is no longer watched.
    closed: bool,
}

#[derive(Clone, Copy)]
enum Pause {
    /// An accept failed; nothing resumes the listener before the time.
    Failed(Instant),
    /// The guest listener had no room; a wake or the time resumes it.
    Room(Instant),
}

impl Pause {
    fn until(self) -> Instant {
        match self {
            Self::Failed(until) | Self::Room(until) => until,
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
            table
                .insert(Arc::new(listener), false)
                .map_err(|_| Error::from(std::io::ErrorKind::OutOfMemory))?;
        }
        Ok(Self {
            table: Mutex::new(table),
            listener_ip,
            sync: Mutex::new(()),
            gateway_ports: GatewayPeerPorts::new(),
            paused: AtomicBool::new(false),
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
            .ok_or_else(|| Error::from(std::io::ErrorKind::OutOfMemory))?
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
            let mut state = lock(&listener.state);
            state.closed = true;
            self.poller.delete(&mut state.socket);
        }
    }

    /// Publishes the guest listener covering the guest address and
    /// `guest_port` on the published listener IP if there is one, or stops
    /// publishing the port if there is none; see the module docs. Call it,
    /// holding no provider lock but a socket's own, after each change to
    /// whether a guest listener covers the port.
    pub(super) fn publish_guest_listener(&self, guest_port: u16) {
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
            (true, None) => self.open_guest_listener(PublishedTcpPort {
                host_address: SocketAddrV4::new(ip, guest_port),
                guest_port,
            }),
            (false, Some(token)) => {
                self.close_guest_listener(guest_port, token);
                false
            }
            (_, published) => published.is_some(),
        };
        self.hook(HookPoint::ListenerPublished(guest_port, published));
    }

    /// Opens and watches a listener publishing a guest listener as
    /// `mapping`, reporting whether it did. A failure leaves the port
    /// unpublished, as the guest's listener works without it.
    fn open_guest_listener(&self, mapping: PublishedTcpPort) -> bool {
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
            return failed(&"out of memory");
        };
        // The event thread finds the listener once it is in the table.
        let watched = self.watch_published_listener(&mut lock(&listener.state), token);
        if let Err(error) = watched {
            self.close_guest_listener(mapping.guest_port, token);
            return failed(&error);
        }
        true
    }

    /// Closes the listener with `token` that publishes the guest listener on
    /// `guest_port`. Clients waiting in its backlog are reset.
    fn close_guest_listener(&self, guest_port: u16, token: u64) {
        let listener = {
            let mut table = lock(&self.published.table);
            table.guest_listeners.remove(&guest_port);
            table.listeners.remove(&token)
        };
        if let Some(listener) = listener {
            let mut state = lock(&listener.state);
            state.closed = true;
            self.poller.delete(&mut state.socket);
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
        match state.pause {
            Some(Pause::Failed(_)) => return,
            Some(Pause::Room(_)) => state.pause = None,
            None => {}
        }
        self.accept_published(&listener, &mut state, token);
    }

    /// Wakes every published listener, so one waiting for room checks for it.
    ///
    /// Posting takes only the `table` leaf and the innermost posted-token
    /// lock, so callers may hold any other lock.
    pub(super) fn wake_published(&self) {
        for token in lock(&self.published.table).listeners.keys() {
            self.posted.post(*token);
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
                self.pause_published(state, Pause::Room(Instant::now() + ROOM_RETRY));
                return;
            }
            let rejected = match state.socket.accept() {
                Ok(socket) if room == PublishedRoom::Available => topology
                    .queue_published_connection(
                        guest_address,
                        socket,
                        &self.published.gateway_ports,
                        self.max_sockets,
                    )
                    .err(),
                Ok(socket) => Some(socket),
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR | Errno::CONNABORTED) => continue,
                Err(_) => {
                    drop(topology);
                    self.pause_published(state, Pause::Failed(Instant::now() + ACCEPT_RETRY));
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
        self.rearm_published(state, token);
    }

    fn pause_published(&self, state: &mut ListenerState, pause: Pause) {
        state.pause = Some(pause);
        self.published.paused.store(true, Ordering::Release);
    }

    fn rearm_published(&self, state: &mut ListenerState, token: u64) {
        let rearmed = self.poller.modify(
            &mut state.socket,
            token,
            Interest::Oneshot {
                read: true,
                write: false,
            },
        );
        if rearmed.is_err() {
            self.pause_published(state, Pause::Failed(Instant::now() + ACCEPT_RETRY));
        }
    }

    /// Resumes each paused listener whose pause ended.
    pub(super) fn resume_published(&self) {
        if !self.published.paused.swap(false, Ordering::AcqRel) {
            return;
        }
        let Some(listeners) = self.published.listeners() else {
            // Try again after the next wait.
            self.published.paused.store(true, Ordering::Release);
            return;
        };
        let now = Instant::now();
        for (token, listener) in listeners {
            let mut state = lock(&listener.state);
            match state.pause {
                _ if state.closed => {}
                Some(pause) if pause.until() <= now => {
                    state.pause = None;
                    self.accept_published(&listener, &mut state, token);
                }
                Some(_) => self.published.paused.store(true, Ordering::Release),
                None => {}
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
        self.published.gateway_ports.leased()
    }

    /// How many guest listeners are published.
    pub(super) fn published_guest_listener_count(&self) -> usize {
        lock(&self.published.table).guest_listeners.len()
    }
}
