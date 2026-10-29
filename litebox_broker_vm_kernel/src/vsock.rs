// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The vsock forwarder: the host uses `AF_VSOCK`, guests Unix sockets. A host
//! connection to guest port `P`, from the VM's socket device ([`Vsock`],
//! [`crate::Config::vsock`]), becomes a broker Unix stream socket connected,
//! without waiting, to the guest listener on the abstract name
//! `litebox-vsock:<P>` (`P` in decimal, e.g., `@litebox-vsock:1024` for the
//! Kata agent's `unix://@litebox-vsock:1024`); the request is refused if that
//! fails (nothing listens there, or its backlog is full). The guest sees an
//! unnamed peer. The forwarder adds no broker operation and does not change
//! the broker core: it is a user of the broker core's Unix sockets.
//!
//! Ends map as on Linux:
//!
//! - The host's `SHUTDOWN` of sending: the Unix socket's write side is shut
//!   down, after the host's data.
//! - The guest's end of data: a `SHUTDOWN` of sending, after the guest's data.
//! - The guest's socket receiving no more (closed, or shut down receiving): a
//!   `SHUTDOWN` of receiving, so the host's sends fail, and what it sent
//!   meanwhile is dropped; the guest's data still goes to the host.
//! - The host's `SHUTDOWN` of receiving: the guest's sends fail.
//! - The host's reset: the Unix socket is closed, after the host's data.
//!
//! A connection ended both ways is closed on the device, which keeps it until
//! the host resets it. From when the guest's socket can neither send nor
//! receive, the connection has [`CLOSE_TIMEOUT`] to deliver the guest's data
//! and be reset by the host; then it is forgotten (reset), whatever is left.
//! The broker core does not tell the guest's close from its socket being shut
//! down both ways, so the timeout also starts when the guest shuts down both
//! ways, or shuts down sending after the host did, while it keeps its socket
//! open: then, unlike on Linux, a host that takes none of the guest's data in
//! time loses what is left of it.
//!
//! The host and guests can make more work than a poll should do: each poll
//! answers at most `MAX_REQUESTS_PER_POLL` requests and moves at most
//! `MAX_BYTES_PER_FLOW` bytes per direction of a connection and
//! `MAX_BYTES_PER_POLL` in all; the next poll is then due `BUSY_INTERVAL`
//! later. A send that fails for want of broker memory is retried after
//! `POLL_INTERVAL`, as freeing memory does not notify.
//!
//! The forwarder's process has no runner, parent or children, and never
//! exits. It exists only with the virtual init, and is created right after
//! it, so it is process 2 and does not take the broker's terminal, which the
//! first root process does; guests can signal it, to no effect, as the
//! virtual init. Guest port names are not reserved: a guest can squat one;
//! the VM, not a guest, is the isolation boundary.
//!
//! Locks: the forwarder's, then the device's (each [`Vsock`] call) or the
//! broker core's, never both. A CPU that finds another polling does not wait
//! for it. The forwarder's sockets' readiness only notifies every CPU
//! ([`cpu::notify_all`]), without taking the forwarder's lock.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Bound;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::unix_socket::{self, Received};
use litebox_broker_core::{BrokerCore, BrokerError, BrokerProcess, CallerCredential};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::{FileOpenFlags, FileUser};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::socket::{ShutdownMode, SocketType};
use litebox_broker_protocol::unix_socket::{MAX_UNIX_SOCKET_TRANSFER_SIZE, UnixSocketAddress};
use litebox_hal::virtio::vsock::ConnectionId;
use litebox_platform::time::Instant as _;
use litebox_platform_vm_kernel::{Instant, cpu};

/// The VM's socket device, as the forwarder drives it (see
/// [`VirtioVsock`](litebox_hal::virtio::vsock::VirtioVsock)). Only
/// [`Self::take_request`], [`Self::read`], [`Self::write`],
/// [`Self::is_closed`] and [`Self::forget`] first take what the device
/// returned; the others take nothing new, so a request just taken is still
/// one when it is accepted.
pub trait Vsock: Sync {
    /// The next connection the host requested, to accept or refuse.
    fn take_request(&self) -> Option<ConnectionId>;

    /// Accepts a requested connection; false if it is not one.
    fn accept(&self, id: ConnectionId) -> bool;

    /// Refuses a requested connection.
    fn refuse(&self, id: ConnectionId);

    /// Copies received data into `output`: how much, or `None` at the end of
    /// the stream.
    fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize>;

    /// Queues as much of `bytes` as the host takes now: how much, or `None`
    /// if the connection takes no more.
    fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize>;

    /// Shuts down sending, after what was written.
    fn shutdown(&self, id: ConnectionId);

    /// Shuts down receiving: the host's sends fail. Data already received
    /// can still be read; data the host sent before it knew is dropped.
    fn shutdown_receiving(&self, id: ConnectionId);

    /// Shuts the connection down both ways, after what was written; it is
    /// closed once the host resets it.
    fn close(&self, id: ConnectionId);

    /// Whether the connection is gone and its data read, or unknown.
    fn is_closed(&self, id: ConnectionId) -> bool;

    /// Ends the connection, resetting it unless it is gone, and frees its
    /// slot.
    fn forget(&self, id: ConnectionId);

    /// Takes whether the calls since the last of these took something from
    /// the device, or stopped at a budget with more left, which it does not
    /// wake the broker for again (e.g., data for a connection whose turn in
    /// the poll is over).
    fn take_backlog(&self) -> bool;

    /// Whether the device wakes the broker as it changes; else the forwarder
    /// polls it.
    fn interrupts(&self) -> bool;
}

/// How long a connection closed both ways waits for the host's reset before
/// it is forgotten (reset) anyway, as Linux's `VSOCK_CLOSE_TIMEOUT`.
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);

/// How often a device that does not interrupt is polled, and a send the
/// broker had no memory for retried (freeing memory does not notify).
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How soon a poll that left work follows the last: soon, but not at once,
/// as a deadline that is due interrupts every running process.
const BUSY_INTERVAL: Duration = Duration::from_millis(1);

/// Bytes buffered per direction of a connection, between the device and the
/// Unix socket.
const CHUNK: usize = 16 * 1024;

// So a Unix socket transfer of a chunk is not refused.
const _: () = assert!(CHUNK <= MAX_UNIX_SOCKET_TRANSFER_SIZE as usize);

/// Bytes moved (or dropped) per direction of a connection per poll.
const MAX_BYTES_PER_FLOW: usize = 64 * 1024;

/// Bytes moved (or dropped) per poll, in all; the rest waits for the next
/// poll, which starts with the connections this one did not get to.
const MAX_BYTES_PER_POLL: usize = 256 * 1024;

/// Host requests answered per poll; the rest wait for the next poll.
const MAX_REQUESTS_PER_POLL: usize = 8;

/// The forwarder's Unix sockets act as this user, which abstract names do
/// not check.
const USER: FileUser = FileUser::ROOT;

/// Bytes on their way from one end to the other: `bytes[start..end]`. The
/// buffer is allocated (and zeroed) once, on the first refill, as polls run on
/// every broker event.
struct Pending {
    bytes: Vec<u8>,
    start: usize,
    end: usize,
}

impl Pending {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            start: 0,
            end: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.start == self.end
    }

    fn rest(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }

    fn consume(&mut self, len: usize) {
        self.start += len;
        if self.is_empty() {
            (self.start, self.end) = (0, 0);
        }
    }

    /// Refills the empty buffer with up to `max` (at most [`CHUNK`]) bytes
    /// from `fill`, which returns how many it wrote; `None`, without calling
    /// it, if the buffer cannot be allocated (the host's traffic must not
    /// abort the kernel).
    fn refill<T>(
        &mut self,
        max: usize,
        fill: impl FnOnce(&mut [u8]) -> T,
        len: impl FnOnce(&T) -> usize,
    ) -> Option<T> {
        debug_assert!(self.is_empty());
        if self.bytes.len() < CHUNK {
            self.bytes
                .try_reserve_exact(CHUNK - self.bytes.len())
                .ok()?;
            self.bytes.resize(CHUNK, 0);
        }
        let max = max.min(CHUNK);
        let result = fill(&mut self.bytes[..max]);
        (self.start, self.end) = (0, len(&result).min(max));
        Some(result)
    }
}

/// A direction of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Open,
    /// Its source sends no more; what it sent is still to be delivered.
    Ending,
    /// What it sent is delivered, and its end passed on, or there is no one
    /// to deliver to (what its source still sends is dropped).
    Ended,
}

struct Connection {
    socket: ObjectHandle,
    /// From the host, not yet sent to the Unix socket.
    to_guest: Pending,
    /// Host to guest: its end shuts down the Unix socket's write side.
    inbound: Flow,
    /// From the Unix socket, not yet written to the device.
    to_host: Pending,
    /// Guest to host: its end shuts down the device connection's sending
    /// side.
    outbound: Flow,
    /// When the connection is forgotten, whatever is left: [`CLOSE_TIMEOUT`]
    /// after the guest's socket could neither send nor receive, or this end
    /// closed the Unix socket.
    deadline: Option<Instant>,
    /// Closed both ways on the device, waiting for the host's reset until
    /// the deadline; the Unix socket is closed.
    closing: bool,
}

impl Connection {
    fn is_due(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }
}

/// Whether a connection goes on after a step.
enum Step {
    Continue,
    /// Over on both ends, the Unix socket closed: forget the device
    /// connection.
    Release,
}

/// What a send to the guest did.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    /// It sent this many bytes (zero only of none).
    Bytes(usize),
    /// Nothing until the guest makes room, which notifies.
    Full,
    /// Nothing for want of broker memory (e.g., the guest's quota of queued
    /// bytes), which frees without notice.
    Stalled,
    /// The guest's socket receives no more: it is closed, or shut down
    /// receiving.
    Gone,
}

/// A poll's budget, and what it left.
struct Pass {
    now: Instant,
    /// Bytes it may still move (or drop), in all.
    bytes: usize,
    /// It stopped at a budget with more to do.
    busy: bool,
    /// Work waits for memory, which frees without notice.
    stalled: bool,
}

impl Pass {
    /// What a direction of a connection may move.
    fn flow_limit(&self) -> usize {
        self.bytes.min(MAX_BYTES_PER_FLOW)
    }

    /// Counts `moved` bytes against the budget; `limit` was the direction's.
    fn moved(&mut self, moved: usize, limit: usize) {
        self.bytes = self.bytes.saturating_sub(moved);
        if moved >= limit {
            self.busy = true;
        }
    }
}

struct State {
    connections: BTreeMap<ConnectionId, Connection>,
    /// The last poll stopped at a budget with more to do, or left the
    /// device with a backlog.
    busy: bool,
    /// Work waits for memory, which frees without notice.
    stalled: bool,
    /// The connection the last poll's byte budget stopped after: the next
    /// starts after it, so each connection gets its turn.
    stopped_after: Option<ConnectionId>,
    last_poll: Option<Instant>,
}

/// See the [module](self) docs.
pub(crate) struct Forwarder {
    process: Arc<BrokerProcess>,
    sink: Arc<dyn ReadinessSink>,
    device: &'static dyn Vsock,
    /// The kernel clock.
    now: Box<dyn Fn() -> Instant + Send + Sync>,
    state: spin::Mutex<State>,
    /// A poll was asked for, and not yet started: one that found another CPU
    /// polling leaves it to that one, which polls again, or else to
    /// [`Self::next_deadline`], which reports a poll due.
    repoll: AtomicBool,
}

impl Forwarder {
    /// The forwarder for `device`, with its broker process, on the clock
    /// `now`.
    ///
    /// # Errors
    ///
    /// The process cannot be created.
    pub(crate) fn new(
        core: &BrokerCore,
        device: &'static dyn Vsock,
        now: Box<dyn Fn() -> Instant + Send + Sync>,
    ) -> Result<Self, BrokerError> {
        let process = core.create_process(CallerCredential::HostGuaranteed, None)?;
        process.complete_start()?;
        Ok(Self {
            process,
            sink: Arc::new(Sink),
            device,
            now,
            state: spin::Mutex::new(State {
                connections: BTreeMap::new(),
                busy: false,
                stalled: false,
                stopped_after: None,
                last_poll: None,
            }),
            repoll: AtomicBool::new(false),
        })
    }

    /// Takes the host's requests, and moves what each connection can, a
    /// bounded amount. Never waits for another CPU's poll.
    pub(crate) fn poll(&self) {
        self.repoll.store(true, Ordering::SeqCst);
        // Once more for a CPU that asked meanwhile; then, the deadline.
        for _ in 0..2 {
            let Some(mut state) = self.state.try_lock() else {
                return;
            };
            if !self.repoll.swap(false, Ordering::SeqCst) {
                return;
            }
            self.poll_locked(&mut state);
            drop(state);
            if !self.repoll.load(Ordering::SeqCst) {
                return;
            }
        }
    }

    /// When the forwarder must next poll, if before the device changes: soon
    /// if a poll is asked for or left work, at the earliest close timeout,
    /// or, for a device that does not interrupt (or work waiting for memory),
    /// its poll interval.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let soon = || Some(after((self.now)(), BUSY_INTERVAL));
        if self.repoll.load(Ordering::SeqCst) {
            return soon();
        }
        // Another CPU polls, and then has its own deadline.
        let Some(state) = self.state.try_lock() else {
            return soon();
        };
        let last_poll = state.last_poll?;
        if state.busy {
            return Some(after(last_poll, BUSY_INTERVAL));
        }
        let poll =
            (state.stalled || !self.device.interrupts()).then(|| after(last_poll, POLL_INTERVAL));
        state
            .connections
            .values()
            .filter_map(|connection| connection.deadline)
            .chain(poll)
            .min()
    }

    fn poll_locked(&self, state: &mut State) {
        let mut pass = Pass {
            now: (self.now)(),
            bytes: MAX_BYTES_PER_POLL,
            busy: false,
            stalled: false,
        };
        state.last_poll = Some(pass.now);
        let mut requests = 0;
        while requests < MAX_REQUESTS_PER_POLL
            && let Some(id) = self.device.take_request()
        {
            requests += 1;
            match self.open(id) {
                // The device takes nothing new before `accept`, so this is
                // still a request, and the guest never gets a connection
                // the host gave up on.
                Some(socket) if self.device.accept(id) => {
                    state.connections.insert(
                        id,
                        Connection {
                            socket,
                            to_guest: Pending::new(),
                            inbound: Flow::Open,
                            to_host: Pending::new(),
                            outbound: Flow::Open,
                            deadline: None,
                            closing: false,
                        },
                    );
                }
                Some(socket) => self.close_socket(socket),
                None => self.device.refuse(id),
            }
        }
        // More may wait.
        pass.busy |= requests == MAX_REQUESTS_PER_POLL;
        // From after where the last poll stopped, around once; the table only
        // shrinks after the loop.
        let start = state.stopped_after.take();
        let mut cursor = start;
        let mut wrapped = start.is_none();
        let mut released = Vec::new();
        loop {
            let next = match cursor {
                Some(after) => state
                    .connections
                    .range((Bound::Excluded(after), Bound::Unbounded))
                    .next(),
                None => state.connections.iter().next(),
            }
            .map(|(&id, _)| id);
            let id = match next {
                Some(id) if !(wrapped && start.is_some_and(|start| id > start)) => id,
                None if !wrapped => {
                    (cursor, wrapped) = (None, true);
                    continue;
                }
                _ => break,
            };
            cursor = Some(id);
            if pass.bytes == 0 {
                pass.busy = true;
                break;
            }
            let connection = state
                .connections
                .get_mut(&id)
                .expect("connections are removed only below");
            if let Step::Release = self.step(id, connection, &mut pass) {
                released.push(id);
            }
            if pass.bytes == 0 {
                state.stopped_after = Some(id);
            }
        }
        for id in released {
            self.device.forget(id);
            state.connections.remove(&id);
        }
        state.busy = pass.busy || self.device.take_backlog();
        state.stalled = pass.stalled;
    }

    /// A Unix socket connected to the listener on `id`'s guest port; `None`
    /// if it cannot be.
    fn open(&self, id: ConnectionId) -> Option<ObjectHandle> {
        let socket = match unix_socket::create(
            &self.process,
            SocketType::Stream,
            FileOpenFlags::NONBLOCKING,
            &self.sink,
        ) {
            Ok(socket) => socket,
            Err(error) => {
                log::debug!("vsock: refusing {id:?}: no socket: {error:?}");
                return None;
            }
        };
        let guest = UnixSocketAddress::Abstract(guest_name(id.guest_port));
        match unix_socket::connect(&self.process, socket, &guest, USER) {
            Ok(Ok(())) => Some(socket),
            result => {
                log::debug!("vsock: refusing {id:?}: {result:?}");
                self.close_socket(socket);
                None
            }
        }
    }

    fn close_socket(&self, socket: ObjectHandle) {
        if let Err(error) = self.process.close_object_reference(socket) {
            log::debug!("vsock: closing a socket failed: {error:?}");
        }
    }

    /// Moves what `connection` can, both ways, and ends what is over.
    fn step(&self, id: ConnectionId, connection: &mut Connection, pass: &mut Pass) -> Step {
        if connection.closing {
            // What the host sends after the close resets it, and goes
            // nowhere.
            let limit = pass.flow_limit();
            let dropped = self.discard(id, limit);
            pass.moved(dropped, limit);
            return if self.device.is_closed(id) || connection.is_due(pass.now) {
                Step::Release
            } else {
                Step::Continue
            };
        }
        // The guest's socket can neither send nor receive (see the module
        // docs), whether or not its data is delivered.
        if connection.deadline.is_none()
            && self
                .process
                .check_readiness(connection.socket)
                .is_ok_and(|readiness| readiness.contains(ReadinessFlags::CLOSED))
        {
            connection.deadline = Some(after(pass.now, CLOSE_TIMEOUT));
        }
        if connection.is_due(pass.now) {
            // What is left of the guest's is dropped.
            self.close_socket(connection.socket);
            return Step::Release;
        }
        self.to_guest(id, connection, pass);
        self.to_host(id, connection, pass);
        if connection.to_guest.is_empty() && self.device.is_closed(id) {
            // The host reset it (or shut it down both ways), and what it
            // sent is delivered.
            self.close_socket(connection.socket);
            return Step::Release;
        }
        if connection.outbound == Flow::Ending && connection.to_host.is_empty() {
            self.device.shutdown(id);
            connection.outbound = Flow::Ended;
        }
        // Probes whether the guest's socket receives no more; not once this
        // end shut down its write side, which fails sends too.
        if connection.inbound == Flow::Open
            && connection.to_guest.is_empty()
            && self.send(connection.socket, &[]) == Sent::Gone
        {
            self.receives_no_more(id, connection);
        }
        if connection.outbound == Flow::Ended && connection.inbound == Flow::Ended {
            self.device.close(id);
            self.close_socket(connection.socket);
            connection.closing = true;
            connection
                .deadline
                .get_or_insert(after(pass.now, CLOSE_TIMEOUT));
        }
        Step::Continue
    }

    /// The guest's socket receives no more (it is closed, or shut down
    /// receiving): the host is told, so its sends fail, as on Linux, and
    /// what it sent meanwhile is dropped.
    fn receives_no_more(&self, id: ConnectionId, connection: &mut Connection) {
        connection.to_guest = Pending::new();
        connection.inbound = Flow::Ended;
        self.device.shutdown_receiving(id);
    }

    /// Moves the host's data to the Unix socket, and its end. Once the
    /// guest's socket receives no more, see [`Self::receives_no_more`]; the
    /// guest's data still goes to the host.
    fn to_guest(&self, id: ConnectionId, connection: &mut Connection, pass: &mut Pass) {
        let limit = pass.flow_limit();
        let mut moved = 0;
        loop {
            if !connection.to_guest.is_empty() {
                if moved >= limit {
                    break;
                }
                let rest = connection.to_guest.rest();
                match self.send(connection.socket, &rest[..rest.len().min(limit - moved)]) {
                    Sent::Bytes(sent) => {
                        connection.to_guest.consume(sent);
                        moved += sent;
                        if !connection.to_guest.is_empty() {
                            continue;
                        }
                    }
                    Sent::Full => break,
                    Sent::Stalled => {
                        pass.stalled = true;
                        break;
                    }
                    Sent::Gone => self.receives_no_more(id, connection),
                }
            }
            match connection.inbound {
                Flow::Open => {}
                Flow::Ending => {
                    self.shut_down_socket(connection.socket, ShutdownMode::Write);
                    connection.inbound = Flow::Ended;
                    break;
                }
                Flow::Ended => {
                    moved += self.discard(id, limit - moved);
                    break;
                }
            }
            if moved >= limit {
                break;
            }
            match connection.to_guest.refill(
                limit - moved,
                |buffer| self.device.read(id, buffer),
                |read| read.unwrap_or(0),
            ) {
                None => {
                    pass.stalled = true;
                    break;
                }
                Some(Some(0)) => break,
                Some(Some(_)) => {}
                Some(None) => connection.inbound = Flow::Ending,
            }
        }
        pass.moved(moved, limit);
    }

    /// Moves the guest's data to the device, and notes its end.
    fn to_host(&self, id: ConnectionId, connection: &mut Connection, pass: &mut Pass) {
        let limit = pass.flow_limit();
        let mut moved = 0;
        loop {
            if !connection.to_host.is_empty() {
                if moved >= limit {
                    break;
                }
                let rest = connection.to_host.rest();
                let Some(written) = self
                    .device
                    .write(id, &rest[..rest.len().min(limit - moved)])
                else {
                    self.host_receives_no_more(connection);
                    break;
                };
                connection.to_host.consume(written);
                moved += written;
                if !connection.to_host.is_empty() {
                    // Until the host gives credit, or the device returns
                    // buffers, which interrupts; or the next poll.
                    break;
                }
            }
            if connection.outbound != Flow::Open || moved >= limit {
                break;
            }
            // So the guest's sends fail as soon as the host's `SHUTDOWN` of
            // receiving arrives, not after its next send.
            if self.device.write(id, &[]).is_none() {
                self.host_receives_no_more(connection);
                break;
            }
            let received = connection.to_host.refill(
                limit - moved,
                |mut buffer| {
                    unix_socket::receive(
                        &self.process,
                        connection.socket,
                        &mut buffer,
                        false,
                        false,
                        true,
                    )
                },
                |received| match received {
                    Ok(Ok(Received { received, .. })) => *received,
                    _ => 0,
                },
            );
            match received {
                None => {
                    pass.stalled = true;
                    break;
                }
                Some(Ok(Ok(Received { received: 0, .. }))) => connection.outbound = Flow::Ending,
                Some(Ok(Ok(_))) => {}
                // Until the guest sends, which notifies.
                Some(Err(BrokerError::NonBlockingWouldBlock | BrokerError::WouldBlock)) => break,
                Some(Ok(Err(_)) | Err(_)) => connection.outbound = Flow::Ending,
            }
        }
        pass.moved(moved, limit);
    }

    /// The host receives no more (or the connection is gone): the guest's
    /// sends fail from now on, what it sent is dropped, and no `SHUTDOWN`
    /// follows.
    fn host_receives_no_more(&self, connection: &mut Connection) {
        connection.to_host = Pending::new();
        self.shut_down_socket(connection.socket, ShutdownMode::Read);
        connection.outbound = Flow::Ended;
    }

    fn shut_down_socket(&self, socket: ObjectHandle, mode: ShutdownMode) {
        match unix_socket::shutdown(&self.process, socket, mode) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => log::debug!("vsock: shutting down a socket failed: {error:?}"),
            Err(error) => log::debug!("vsock: shutting down a socket failed: {error:?}"),
        }
    }

    /// Reads and drops up to `limit` bytes the host sent on `id`: how many.
    fn discard(&self, id: ConnectionId, limit: usize) -> usize {
        let mut buffer = [0; 4096];
        let mut dropped = 0;
        while dropped < limit {
            let len = buffer.len().min(limit - dropped);
            match self.device.read(id, &mut buffer[..len]) {
                Some(read) if read != 0 => dropped += read,
                _ => break,
            }
        }
        dropped
    }

    /// Sends from the start of `bytes` to the guest.
    fn send(&self, socket: ObjectHandle, bytes: &[u8]) -> Sent {
        match unix_socket::send(&self.process, socket, None, &bytes, USER) {
            Ok(Ok(sent)) => Sent::Bytes(sent),
            Err(BrokerError::NonBlockingWouldBlock | BrokerError::WouldBlock) => Sent::Full,
            Err(BrokerError::ResourceExhausted | BrokerError::OutOfMemory) => Sent::Stalled,
            Ok(Err(_)) | Err(_) => Sent::Gone,
        }
    }
}

/// The abstract name (without its leading NUL) guests listen on for
/// connections to vsock port `port`.
fn guest_name(port: u32) -> Vec<u8> {
    alloc::format!("litebox-vsock:{port}").into_bytes()
}

/// `duration` after `instant`, or the end of time.
fn after(instant: Instant, duration: Duration) -> Instant {
    instant
        .checked_add(duration)
        .unwrap_or(Instant::from_nanos(u64::MAX))
}

/// The forwarder's sockets' readiness: a change (e.g., the guest sent data,
/// or made room) has every CPU poll again, which polls the forwarder.
struct Sink;

impl ReadinessSink for Sink {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(
        &self,
        _handle: ObjectHandle,
        _readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        cpu::notify_all();
        Ok(())
    }

    fn republish(
        &self,
        _handle: ObjectHandle,
        _readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        cpu::notify_all();
        Ok(())
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use core::sync::atomic::AtomicU64;
    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::{BrokerCoreLimits, ObjectRights, PolicyEngine};
    use litebox_broker_protocol::fs::FileMode;
    use litebox_broker_protocol::unix_socket::{UNIX_SOCKET_BUFFER_SIZE, UnixSocketError};

    const PORT: u32 = 1024;

    const fn id(guest_port: u32, host_port: u32) -> ConnectionId {
        ConnectionId {
            guest_port,
            host_port,
        }
    }

    /// A connection to [`PORT`].
    const fn on(host_port: u32) -> ConnectionId {
        id(PORT, host_port)
    }

    /// The host's end of a connection, and the device's state of it.
    #[derive(Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "independent ends of a connection, set by the tests"
    )]
    struct HostConnection {
        live: bool,
        /// Reset by either end.
        gone: bool,
        /// Sent by the host, not yet read.
        sent: VecDeque<u8>,
        /// The host sends no more.
        sent_all: bool,
        /// The host receives no more.
        receives_no_more: bool,
        received: Vec<u8>,
        /// How much more the host takes.
        credit: usize,
        /// The forwarder shut down sending.
        shut_down: bool,
        /// The forwarder shut down receiving.
        shut_down_receiving: bool,
        /// The forwarder closed it.
        closed: bool,
    }

    /// What the device returns on a connection.
    enum Returned {
        Data(Vec<u8>),
        Credit(usize),
    }

    #[derive(Default)]
    struct HostState {
        requests: VecDeque<ConnectionId>,
        /// Requests the device takes only on the next read, of any
        /// connection, as the driver may.
        late_requests: VecDeque<ConnectionId>,
        /// What the device takes only as the forwarder checks whether a
        /// connection is closed, after its turn in a poll, as the driver may.
        returned_after_turn: Vec<(ConnectionId, Returned)>,
        connections: BTreeMap<ConnectionId, HostConnection>,
        refused: Vec<ConnectionId>,
        /// Forgotten, and whether they were reset then (not gone).
        forgotten: Vec<(ConnectionId, bool)>,
        /// The device took something since the last `take_backlog`, as the
        /// driver latches it: data read or written, or a control packet sent.
        took: bool,
    }

    /// The host, behind a device that takes what it is given at once, but
    /// for what is late.
    #[derive(Default)]
    struct Host(spin::Mutex<HostState>);

    impl Host {
        fn connect(&self, id: ConnectionId) {
            self.0.lock().requests.push_back(id);
            self.add(id);
        }

        /// As [`Self::connect`], with the request taken on the next read.
        fn connect_late(&self, id: ConnectionId) {
            self.0.lock().late_requests.push_back(id);
            self.add(id);
        }

        fn add(&self, id: ConnectionId) {
            self.0.lock().connections.insert(
                id,
                HostConnection {
                    credit: usize::MAX,
                    ..HostConnection::default()
                },
            );
        }

        /// The device's transport reset.
        fn reset_all(&self) {
            let mut state = self.0.lock();
            let requests: Vec<_> = state.requests.drain(..).collect();
            for id in requests {
                state.connections.remove(&id);
            }
            for connection in state.connections.values_mut() {
                connection.gone = true;
            }
        }

        fn with<T>(&self, id: ConnectionId, f: impl FnOnce(&mut HostConnection) -> T) -> T {
            f(self.0.lock().connections.get_mut(&id).unwrap())
        }

        /// As [`Self::with`], for a control packet the forwarder sends.
        fn control<T>(&self, id: ConnectionId, f: impl FnOnce(&mut HostConnection) -> T) -> T {
            let mut state = self.0.lock();
            state.took = true;
            f(state.connections.get_mut(&id).unwrap())
        }

        fn send(&self, id: ConnectionId, bytes: &[u8]) {
            self.with(id, |connection| connection.sent.extend(bytes));
        }

        fn take_received(&self, id: ConnectionId) -> Vec<u8> {
            self.with(id, |connection| core::mem::take(&mut connection.received))
        }

        /// The device takes `returned` on `id` after its turn in the next
        /// poll.
        fn return_after_turn(&self, id: ConnectionId, returned: Returned) {
            self.0.lock().returned_after_turn.push((id, returned));
        }
    }

    impl Vsock for Host {
        fn take_request(&self) -> Option<ConnectionId> {
            self.0.lock().requests.pop_front()
        }

        fn accept(&self, id: ConnectionId) -> bool {
            self.control(id, |connection| {
                connection.live = !connection.gone;
                connection.live
            })
        }

        fn refuse(&self, id: ConnectionId) {
            let mut state = self.0.lock();
            state.took = true;
            state.connections.remove(&id);
            state.refused.push(id);
        }

        fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
            let mut state = self.0.lock();
            let state = &mut *state;
            state.took |= !state.late_requests.is_empty();
            state.requests.extend(state.late_requests.drain(..));
            let connection = state.connections.get_mut(&id)?;
            if connection.sent.is_empty() {
                let ended = connection.gone
                    || connection.sent_all
                    || connection.closed
                    || connection.shut_down_receiving;
                return (!ended).then_some(0);
            }
            let len = output.len().min(connection.sent.len());
            for (byte, sent) in output.iter_mut().zip(connection.sent.drain(..len)) {
                *byte = sent;
            }
            state.took |= len != 0;
            Some(len)
        }

        fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
            let mut state = self.0.lock();
            let state = &mut *state;
            let connection = state.connections.get_mut(&id)?;
            if !connection.live
                || connection.gone
                || connection.receives_no_more
                || connection.shut_down
            {
                return None;
            }
            let len = bytes.len().min(connection.credit);
            connection.received.extend_from_slice(&bytes[..len]);
            connection.credit -= len;
            state.took |= len != 0;
            Some(len)
        }

        fn shutdown(&self, id: ConnectionId) {
            self.control(id, |connection| connection.shut_down = true);
        }

        fn shutdown_receiving(&self, id: ConnectionId) {
            self.control(id, |connection| connection.shut_down_receiving = true);
        }

        fn close(&self, id: ConnectionId) {
            self.control(id, |connection| {
                connection.shut_down = true;
                connection.closed = true;
            });
        }

        fn is_closed(&self, id: ConnectionId) -> bool {
            let mut state = self.0.lock();
            let state = &mut *state;
            for (returned_on, returned) in state.returned_after_turn.drain(..) {
                state.took = true;
                let Some(connection) = state.connections.get_mut(&returned_on) else {
                    continue;
                };
                match returned {
                    Returned::Data(bytes) => connection.sent.extend(bytes),
                    Returned::Credit(credit) => connection.credit = credit,
                }
            }
            state
                .connections
                .get(&id)
                .is_none_or(|connection| connection.gone && connection.sent.is_empty())
        }

        fn forget(&self, id: ConnectionId) {
            let mut state = self.0.lock();
            state.took = true;
            let gone = state
                .connections
                .remove(&id)
                .is_none_or(|connection| connection.gone);
            state.forgotten.push((id, !gone));
        }

        fn take_backlog(&self) -> bool {
            core::mem::take(&mut self.0.lock().took)
        }

        fn interrupts(&self) -> bool {
            true
        }
    }

    fn guest_socket(guest: &BrokerProcess) -> ObjectHandle {
        let sink: Arc<dyn ReadinessSink> = Arc::new(Sink);
        unix_socket::create(guest, SocketType::Stream, FileOpenFlags::NONBLOCKING, &sink).unwrap()
    }

    /// A listener on guest port `port`.
    fn listen(guest: &BrokerProcess, port: u32, backlog: u32) -> ObjectHandle {
        let listener = guest_socket(guest);
        let name = UnixSocketAddress::Abstract(guest_name(port));
        unix_socket::bind(guest, listener, &name, USER, FileMode::empty())
            .unwrap()
            .unwrap();
        unix_socket::listen(guest, listener, backlog)
            .unwrap()
            .unwrap();
        listener
    }

    /// A forwarder, the host behind its device, and a guest process with a
    /// listener on [`PORT`].
    struct Fixture {
        forwarder: Forwarder,
        host: &'static Host,
        guest: Arc<BrokerProcess>,
        listener: ObjectHandle,
        clock: Arc<AtomicU64>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_limits(BrokerCoreLimits::DEFAULT)
        }

        fn with_limits(limits: BrokerCoreLimits) -> Self {
            // As the VM broker's.
            let core = TestBrokerCoreBuilder::new(PolicyEngine::with_host_guaranteed_rights(
                ObjectRights::all(),
            ))
            .with_limits(limits)
            .build()
            .unwrap();
            let guest = core
                .create_process(CallerCredential::HostGuaranteed, None)
                .unwrap();
            let host: &'static Host = Box::leak(Box::default());
            let clock = Arc::new(AtomicU64::new(1));
            let now = Arc::clone(&clock);
            let forwarder = Forwarder::new(
                &core,
                host,
                Box::new(move || Instant::from_nanos(now.load(Ordering::SeqCst))),
            )
            .unwrap();
            let listener = listen(&guest, PORT, 64);
            Self {
                forwarder,
                host,
                guest,
                listener,
                clock,
            }
        }

        fn now(&self) -> Instant {
            Instant::from_nanos(self.clock.load(Ordering::SeqCst))
        }

        fn advance(&self, duration: Duration) {
            let nanos = u64::try_from(duration.as_nanos()).unwrap();
            self.clock.fetch_add(nanos, Ordering::SeqCst);
        }

        fn poll(&self) {
            self.forwarder.poll();
        }

        fn assert_due_soon(&self) {
            assert_eq!(
                self.forwarder.next_deadline(),
                Some(after(self.now(), BUSY_INTERVAL))
            );
        }

        /// The poll due soon after one the device made progress in, which
        /// then finds nothing new.
        fn trailing_poll(&self) {
            self.assert_due_soon();
            self.poll();
        }

        /// The host connects from `host_port`, and the guest accepts it.
        fn connect(&self, host_port: u32) -> ObjectHandle {
            self.host.connect(on(host_port));
            self.poll();
            self.accept()
        }

        fn accept(&self) -> ObjectHandle {
            let sink: Arc<dyn ReadinessSink> = Arc::new(Sink);
            unix_socket::accept(
                &self.guest,
                self.listener,
                FileOpenFlags::NONBLOCKING,
                &sink,
            )
            .unwrap()
            .unwrap()
        }

        fn send(&self, socket: ObjectHandle, bytes: &[u8]) -> Result<usize, UnixSocketError> {
            unix_socket::send(&self.guest, socket, None, &bytes, USER).unwrap()
        }

        /// What the guest can receive now; `None` at the end of the stream.
        fn receive(&self, socket: ObjectHandle) -> Option<Vec<u8>> {
            let mut received = Vec::new();
            loop {
                let mut buffer = vec![0; CHUNK];
                match unix_socket::receive(&self.guest, socket, &mut buffer, false, false, true) {
                    Ok(Ok(Received { received: 0, .. })) => {
                        return (!received.is_empty()).then_some(received);
                    }
                    Ok(Ok(Received { received: len, .. })) => {
                        received.extend_from_slice(&buffer[..len]);
                    }
                    Err(BrokerError::NonBlockingWouldBlock) => return Some(received),
                    other => panic!("receive: {other:?}"),
                }
            }
        }

        fn close(&self, socket: ObjectHandle) {
            self.guest.close_object_reference(socket).unwrap();
        }

        fn forgotten(&self) -> Vec<(ConnectionId, bool)> {
            core::mem::take(&mut self.host.0.lock().forgotten)
        }
    }

    #[test]
    fn requests_nothing_listens_for_are_refused() {
        let f = Fixture::new();
        f.host.connect(id(PORT + 1, 5));
        f.host.connect(on(6));
        f.poll();
        assert_eq!(f.host.0.lock().refused, [id(PORT + 1, 5)]);
        f.accept();
        assert!(f.host.with(on(6), |connection| connection.live));
    }

    #[test]
    fn requests_beyond_a_full_backlog_are_refused() {
        let f = Fixture::new();
        // Two connections wait at most.
        listen(&f.guest, PORT + 1, 1);
        for host_port in 0..4 {
            f.host.connect(id(PORT + 1, host_port));
        }
        f.poll();
        assert_eq!(f.host.0.lock().refused, [id(PORT + 1, 2), id(PORT + 1, 3)]);
        for host_port in 0..2 {
            assert!(
                f.host
                    .with(id(PORT + 1, host_port), |connection| connection.live)
            );
        }
    }

    #[test]
    fn data_and_ends_pass_both_ways() {
        let f = Fixture::new();
        let socket = f.connect(7);
        f.host.send(on(7), b"ping");
        f.host.with(on(7), |connection| connection.sent_all = true);
        f.poll();
        assert_eq!(f.receive(socket), Some(b"ping".to_vec()));
        assert_eq!(f.receive(socket), None);
        // After the host's end, the guest still sends.
        assert_eq!(f.send(socket, b"pong"), Ok(4));
        f.close(socket);
        f.poll();
        assert_eq!(f.host.take_received(on(7)), b"pong");
        // Closed both ways, until the host resets it.
        assert!(f.host.with(on(7), |connection| connection.closed));
        assert_eq!(f.forgotten(), []);
        f.host.with(on(7), |connection| connection.gone = true);
        f.poll();
        assert_eq!(f.forgotten(), [(on(7), false)]);
    }

    #[test]
    fn host_data_after_the_guest_closes_does_not_lose_the_guests() {
        let f = Fixture::new();
        let socket = f.connect(7);
        f.host.send(on(7), b"request");
        f.poll();
        assert_eq!(f.receive(socket), Some(b"request".to_vec()));
        // The host takes the reply slowly.
        f.host.with(on(7), |connection| connection.credit = 1000);
        let reply: Vec<u8> = (0..100_000u32).map(|i| i.to_le_bytes()[0]).collect();
        assert_eq!(f.send(socket, &reply), Ok(reply.len()));
        f.close(socket);
        f.host.send(on(7), b"more");
        for _ in 0..200 {
            f.poll();
            f.host.with(on(7), |connection| connection.credit = 1000);
        }
        // What the host sent is dropped, what the guest sent arrived, and
        // the end is a close, not a reset.
        assert_eq!(f.host.take_received(on(7)), reply);
        f.host.with(on(7), |connection| {
            assert!(connection.sent.is_empty());
            assert!(connection.shut_down_receiving);
            assert!(connection.closed && !connection.gone);
        });
        assert_eq!(f.forgotten(), []);
    }

    #[test]
    fn guests_shutting_down_receiving_still_send() {
        let f = Fixture::new();
        let socket = f.connect(7);
        unix_socket::shutdown(&f.guest, socket, ShutdownMode::Read)
            .unwrap()
            .unwrap();
        f.host.send(on(7), b"dropped");
        f.poll();
        assert_eq!(f.send(socket, b"still"), Ok(5));
        f.poll();
        assert_eq!(f.host.take_received(on(7)), b"still");
        f.host.with(on(7), |connection| {
            assert!(connection.sent.is_empty());
            assert!(connection.shut_down_receiving && !connection.shut_down);
        });
        assert_eq!(f.forgotten(), []);
        f.trailing_poll();
        // Not a close: no deadline.
        assert_eq!(f.forwarder.next_deadline(), None);
    }

    #[test]
    fn hosts_shutting_down_receiving_fail_guest_sends() {
        let f = Fixture::new();
        let socket = f.connect(7);
        f.host
            .with(on(7), |connection| connection.receives_no_more = true);
        // Before the guest sends anything.
        f.poll();
        assert_eq!(f.send(socket, b"fails"), Err(UnixSocketError::BrokenPipe));
        // The host's data still arrives.
        f.host.send(on(7), b"data");
        f.poll();
        assert_eq!(f.receive(socket), Some(b"data".to_vec()));
    }

    /// The guest sends a reply the host gives no credit for, and closes its
    /// socket; the close's timeout is due at the returned instant.
    fn close_with_data_the_host_takes_no_credit_for() -> (Fixture, Instant) {
        let f = Fixture::new();
        let socket = f.connect(7);
        f.host.with(on(7), |connection| connection.credit = 0);
        assert_eq!(f.send(socket, b"reply"), Ok(5));
        f.poll();
        f.close(socket);
        f.poll();
        // The host is told before the data is delivered.
        f.host.with(on(7), |connection| {
            assert!(connection.shut_down_receiving && !connection.shut_down);
        });
        f.trailing_poll();
        let timeout = after(f.now(), CLOSE_TIMEOUT);
        assert_eq!(f.forwarder.next_deadline(), Some(timeout));
        f.advance(CLOSE_TIMEOUT.checked_sub(Duration::from_nanos(1)).unwrap());
        f.poll();
        assert_eq!(f.forgotten(), []);
        (f, timeout)
    }

    #[test]
    fn closes_time_out_while_the_host_gives_no_credit() {
        let (f, _) = close_with_data_the_host_takes_no_credit_for();
        assert_eq!(f.host.take_received(on(7)), b"");
        f.advance(Duration::from_nanos(1));
        f.poll();
        assert_eq!(f.forgotten(), [(on(7), true)]);
        f.trailing_poll();
        assert_eq!(f.forwarder.next_deadline(), None);
    }

    #[test]
    fn closes_deliver_everything_if_the_host_gives_credit_in_time() {
        let (f, timeout) = close_with_data_the_host_takes_no_credit_for();
        f.host
            .with(on(7), |connection| connection.credit = usize::MAX);
        f.poll();
        assert_eq!(f.host.take_received(on(7)), b"reply");
        assert!(f.host.with(on(7), |connection| connection.closed));
        f.trailing_poll();
        // The close's time still bounds the wait for the host's reset.
        assert_eq!(f.forwarder.next_deadline(), Some(timeout));
        f.advance(Duration::from_nanos(1));
        f.poll();
        assert_eq!(f.forgotten(), [(on(7), true)]);
    }

    #[test]
    fn sends_the_broker_has_no_memory_for_are_retried() {
        let mut limits = BrokerCoreLimits::DEFAULT;
        limits.max_unix_socket_bytes_per_process = 1000;
        let f = Fixture::with_limits(limits);
        let socket = f.connect(7);
        f.host.send(on(7), &[1; 600]);
        f.poll();
        f.host.send(on(7), &[2; 600]);
        f.poll();
        f.trailing_poll();
        // Not the guest's end: retried later.
        assert_eq!(
            f.forwarder.next_deadline(),
            Some(after(f.now(), POLL_INTERVAL))
        );
        assert_eq!(f.receive(socket), Some(vec![1; 600]));
        f.poll();
        assert_eq!(f.receive(socket), Some(vec![2; 600]));
        assert!(
            f.host
                .with(on(7), |connection| !connection.gone && !connection.closed)
        );
        assert_eq!(f.forgotten(), []);
    }

    #[test]
    fn requests_are_answered_a_few_per_poll() {
        let f = Fixture::new();
        for host_port in 0..20 {
            f.host.connect(id(PORT + 1, host_port));
        }
        f.poll();
        assert_eq!(f.host.0.lock().refused.len(), MAX_REQUESTS_PER_POLL);
        f.assert_due_soon();
        f.poll();
        f.poll();
        assert_eq!(f.host.0.lock().refused.len(), 20);
        f.poll();
        assert_eq!(f.forwarder.next_deadline(), None);
    }

    #[test]
    fn bytes_are_moved_a_bounded_amount_per_poll_each_connection_in_turn() {
        let f = Fixture::new();
        let count = MAX_BYTES_PER_POLL / MAX_BYTES_PER_FLOW + 1;
        let ports = 0..u32::try_from(count).unwrap();
        let sockets: Vec<_> = ports.clone().map(|port| f.connect(port)).collect();
        for port in ports {
            f.host.send(on(port), &vec![1; 2 * MAX_BYTES_PER_FLOW]);
        }
        let received = |f: &Fixture| -> Vec<usize> {
            sockets
                .iter()
                .map(|&socket| f.receive(socket).unwrap().len())
                .collect()
        };
        f.poll();
        let mut expected = vec![MAX_BYTES_PER_FLOW; count];
        expected[count - 1] = 0;
        assert_eq!(received(&f), expected);
        f.assert_due_soon();
        // The next starts with the one left out.
        f.poll();
        let mut expected = vec![MAX_BYTES_PER_FLOW; count];
        expected[count - 1 - 1] = 0;
        assert_eq!(received(&f), expected);
    }

    #[test]
    fn byte_limits_are_never_exceeded() {
        let f = Fixture::new();
        let count = MAX_BYTES_PER_POLL / MAX_BYTES_PER_FLOW + 1;
        let sockets: Vec<_> = (0..u32::try_from(count).unwrap())
            .map(|port| f.connect(port))
            .collect();
        // So the last's share of the poll's budget is no multiple of a chunk.
        f.host.send(on(0), &[1; 1000]);
        for port in 1..u32::try_from(count).unwrap() {
            f.host.send(on(port), &vec![1; 2 * MAX_BYTES_PER_FLOW]);
        }
        f.poll();
        let received: Vec<_> = sockets
            .iter()
            .map(|&socket| f.receive(socket).unwrap().len())
            .collect();
        assert!(received.iter().all(|&len| len <= MAX_BYTES_PER_FLOW));
        assert_eq!(received.iter().sum::<usize>(), MAX_BYTES_PER_POLL);
    }

    #[test]
    fn requests_taken_while_moving_data_are_answered_soon() {
        let f = Fixture::new();
        let _socket = f.connect(7);
        f.poll();
        assert_eq!(f.forwarder.next_deadline(), None);
        // Taken while reading connection 7, after requests were answered.
        f.host.connect_late(on(8));
        f.poll();
        f.assert_due_soon();
        f.poll();
        f.accept();
        assert!(f.host.with(on(8), |connection| connection.live));
    }

    #[test]
    fn data_and_credit_taken_after_a_connections_turn_are_used_soon() {
        let f = Fixture::new();
        let socket = f.connect(7);
        f.host.with(on(7), |connection| connection.credit = 0);
        assert_eq!(f.send(socket, b"reply"), Ok(5));
        f.poll();
        assert_eq!(f.forwarder.next_deadline(), None);
        f.host
            .return_after_turn(on(7), Returned::Data(b"late".to_vec()));
        f.host
            .return_after_turn(on(7), Returned::Credit(usize::MAX));
        f.poll();
        assert_eq!(f.receive(socket), Some(Vec::new()));
        assert_eq!(f.host.take_received(on(7)), b"");
        f.assert_due_soon();
        f.poll();
        assert_eq!(f.receive(socket), Some(b"late".to_vec()));
        assert_eq!(f.host.take_received(on(7)), b"reply");
        f.trailing_poll();
        assert_eq!(f.forwarder.next_deadline(), None);
    }

    #[test]
    fn stalled_connections_leave_no_polls_due() {
        let f = Fixture::new();
        let socket = f.connect(7);
        // The host gives no credit, and sends more than the guest's socket
        // holds.
        f.host.with(on(7), |connection| connection.credit = 0);
        assert_eq!(f.send(socket, b"reply"), Ok(5));
        let capacity = usize::try_from(UNIX_SOCKET_BUFFER_SIZE).unwrap();
        f.host.send(on(7), &vec![1; 2 * capacity]);
        let unread = || f.host.with(on(7), |connection| connection.sent.len());
        // Until the guest's socket is full.
        loop {
            let before = unread();
            f.poll();
            if unread() == before {
                break;
            }
        }
        assert_ne!(unread(), 0);
        let mut polls = 0;
        while f.forwarder.next_deadline().is_some() {
            assert!(polls < 2, "still due after {polls} polls");
            f.poll();
            polls += 1;
        }
        for _ in 0..5 {
            f.poll();
            assert_eq!(f.forwarder.next_deadline(), None);
        }
        assert_eq!(f.host.take_received(on(7)), b"");
    }

    #[test]
    fn a_transport_reset_ends_live_connections_after_their_data() {
        let f = Fixture::new();
        let first = f.connect(7);
        let second = f.connect(8);
        f.host.send(on(7), b"last");
        f.host.reset_all();
        f.poll();
        assert_eq!(f.receive(first), Some(b"last".to_vec()));
        assert_eq!(f.receive(first), None);
        assert_eq!(f.receive(second), None);
        assert_eq!(f.send(second, b"lost"), Err(UnixSocketError::BrokenPipe));
        assert_eq!(f.forgotten(), [(on(7), false), (on(8), false)]);
        f.trailing_poll();
        assert_eq!(f.forwarder.next_deadline(), None);
    }
}
