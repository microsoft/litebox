// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Published TCP ports: host listeners whose clients reach guest listeners.
//!
//! The provider listens on each published host address from its start until
//! it drops. The event thread accepts each host client and queues its
//! connection on the guest listener covering the published guest address, as
//! an external connection with a gateway peer. With no such listener, it
//! accepts and resets the client, which learns at its first read that the
//! guest is not serving. While the listener has no room (a full backlog, or no
//! room under [`MAX_QUEUED_PUBLISHED_CONNECTIONS`] or the global socket
//! limit), it stops accepting, so clients wait in the host listener's own
//! backlog, as they would in a full Linux backlog; the guest's next accept,
//! or a periodic check, resumes it.
//!
//! Each listener is watched for one read event at a time, under a token with
//! [`PUBLISHED_EVENT_TOKEN_FLAG`]. An event accepts at most
//! [`MAX_ACCEPTS_PER_EVENT`] clients, then watches again, so one busy port
//! cannot starve other sockets. An accept that fails other than for one
//! connection leaves the listener unwatched for [`ACCEPT_RETRY`], rather
//! than spin.
//!
//! A listener's lock is taken only by the event thread and the provider's
//! drop. `topology` may be taken under it, never the reverse.

use std::io::{Error, Result as IoResult};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use litebox_broker_core::socket::{GatewayPeerPorts, PublishedTcpPort};

use super::host::{Errno, HostErrno as _, HostPoller as _, HostSocket as _, Interest, Socket};
use super::tcp::{PublishedRoom, reset_host_connection};
use super::{HookPoint, ProviderCore, lock};

/// Flag of the event tokens of published host listeners; the rest of a
/// token is the listener's index. Socket IDs stay below it.
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
    listeners: Vec<PublishedListener>,
    /// Peers of published connections, from queueing until their sockets
    /// close.
    pub(super) gateway_ports: GatewayPeerPorts,
    /// Some listener is paused.
    paused: AtomicBool,
}

struct PublishedListener {
    mapping: PublishedTcpPort,
    state: Mutex<ListenerState>,
}

struct ListenerState {
    socket: Socket,
    /// Why, and until when, the listener is not watched.
    pause: Option<Pause>,
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
    /// Listens on each mapping's host address, failing if one is taken.
    pub(super) fn bind(mappings: &[PublishedTcpPort]) -> IoResult<Self> {
        let mut listeners = Vec::new();
        listeners.try_reserve_exact(mappings.len())?;
        for mapping in mappings {
            let socket = Socket::tcp_listener(mapping.host_address, HOST_LISTEN_BACKLOG).map_err(
                |error| {
                    let error = Error::from(error);
                    Error::new(
                        error.kind(),
                        format!(
                            "cannot publish guest TCP port {} on {}: {error}",
                            mapping.guest_port, mapping.host_address
                        ),
                    )
                },
            )?;
            listeners.push(PublishedListener {
                mapping: *mapping,
                state: Mutex::new(ListenerState {
                    socket,
                    pause: None,
                }),
            });
        }
        Ok(Self {
            listeners,
            gateway_ports: GatewayPeerPorts::new(),
            paused: AtomicBool::new(false),
        })
    }

    /// Returns the event token of the listener at `index`.
    fn token(index: usize) -> u64 {
        PUBLISHED_EVENT_TOKEN_FLAG | index as u64
    }

    /// Returns how many listeners there are.
    pub(super) fn len(&self) -> usize {
        self.listeners.len()
    }
}

impl ProviderCore {
    /// Watches every published listener, once the provider is shared with
    /// the event thread.
    pub(super) fn watch_published(&self) -> IoResult<()> {
        for (index, listener) in self.published.listeners.iter().enumerate() {
            self.poller
                .add(
                    &mut lock(&listener.state).socket,
                    PublishedPorts::token(index),
                    Interest::Oneshot {
                        read: true,
                        write: false,
                    },
                )
                .map_err(Error::from)?;
        }
        Ok(())
    }

    /// Stops watching every published listener before they close.
    pub(super) fn unwatch_published(&mut self) {
        for listener in &mut self.published.listeners {
            let state = listener
                .state
                .get_mut()
                .expect("socket provider lock poisoned");
            self.poller.delete(&mut state.socket);
        }
    }

    /// Accepts the clients of the published listener with event `token`,
    /// unless an accept failure paused it. The event is a host event, or a
    /// wake from [`Self::wake_published`].
    pub(super) fn handle_published_event(&self, token: u64) {
        let index = usize::try_from(token & !PUBLISHED_EVENT_TOKEN_FLAG).unwrap_or(usize::MAX);
        let Some(listener) = self.published.listeners.get(index) else {
            return;
        };
        let mut state = lock(&listener.state);
        match state.pause {
            Some(Pause::Failed(_)) => return,
            Some(Pause::Room(_)) => state.pause = None,
            None => {}
        }
        self.accept_published(listener, &mut state, token);
    }

    /// Wakes every published listener, so one waiting for room checks for it.
    ///
    /// Posting takes only the innermost posted-token lock, so callers may hold
    /// any other lock.
    pub(super) fn wake_published(&self) {
        for index in 0..self.published.len() {
            self.posted.post(PublishedPorts::token(index));
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
        let now = Instant::now();
        for (index, listener) in self.published.listeners.iter().enumerate() {
            let mut state = lock(&listener.state);
            match state.pause {
                Some(pause) if pause.until() <= now => {
                    state.pause = None;
                    self.accept_published(listener, &mut state, PublishedPorts::token(index));
                }
                Some(_) => self.published.paused.store(true, Ordering::Release),
                None => {}
            }
        }
    }
}

#[cfg(test)]
impl ProviderCore {
    /// The host address the published listener at `index` listens on.
    pub(super) fn published_host_address(&self, index: usize) -> std::net::SocketAddrV4 {
        lock(&self.published.listeners[index].state)
            .socket
            .local_address()
            .unwrap()
    }

    /// How many gateway peer ports are leased.
    pub(super) fn gateway_peer_count(&self) -> usize {
        self.published.gateway_ports.leased()
    }
}
