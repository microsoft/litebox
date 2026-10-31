// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The provider through the broker core, as runner processes use it, on a
//! device the test plays: the host behind it.

use super::*;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::socket::{ReceiveFlags, SendFlags};

use crate::readiness::ReadinessSink;
use crate::test_support::TestBrokerCoreBuilder;
use crate::vsock::{self as core_vsock, AcceptedVsockSocket};
use crate::{BrokerProcess, CallerCredential, ObjectRights, PolicyEngine, VsockPolicy};

const GUEST_CID: u32 = 7;
/// The first ephemeral port.
const SEED: u32 = 50_000;
const PORT: u32 = 1024;
/// The guest's connects the device holds at once, as the VM's.
const MAX_USER_CONNECTIONS: usize = 16;

const READ: ReadinessFlags = ReadinessFlags::READ;
const WRITE: ReadinessFlags = ReadinessFlags::WRITE;
const HANGUP: ReadinessFlags = ReadinessFlags::HANGUP;
const ERROR: ReadinessFlags = ReadinessFlags::ERROR;
const CLOSED: ReadinessFlags = ReadinessFlags::CLOSED;
const NONE: ReadinessFlags = ReadinessFlags(0);

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
    /// The guest asked for it.
    by_guest: bool,
    /// The guest asked for it, and the host has yet to answer.
    connecting: bool,
    live: bool,
    /// Reset by either end, or lost to a transport reset.
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
    /// The guest shut down sending.
    shut_down_sending: bool,
    /// The guest shut down receiving.
    shut_down_receiving: bool,
}

impl HostConnection {
    fn takes_no_more(&self) -> bool {
        !self.live || self.gone || self.receives_no_more || self.shut_down_sending
    }
}

#[derive(Default)]
struct HostState {
    guest_cid: u64,
    requests: VecDeque<ConnectionId>,
    connections: BTreeMap<ConnectionId, HostConnection>,
    refused: Vec<ConnectionId>,
    /// Forgotten, and whether they were reset then (not gone).
    forgotten: Vec<(ConnectionId, bool)>,
    /// The connections the guest asked for.
    asked: Vec<ConnectionId>,
    backlog: bool,
}

/// The test's clock: nanoseconds since its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TestInstant(u64);

impl Instant for TestInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    fn checked_add(&self, duration: Duration) -> Option<Self> {
        let nanos = u64::try_from(duration.as_nanos()).ok()?;
        self.0.checked_add(nanos).map(Self)
    }
}

/// The host, behind a device that takes what it is given at once.
struct Host(spin::Mutex<HostState>);

impl Host {
    fn new() -> Arc<Self> {
        Arc::new(Self(spin::Mutex::new(HostState {
            guest_cid: GUEST_CID.into(),
            ..HostState::default()
        })))
    }

    /// The host requests connection `id`.
    fn connect(&self, id: ConnectionId) {
        let mut state = self.0.lock();
        state.requests.push_back(id);
        state.connections.insert(
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
        state
            .connections
            .retain(|_, connection| !connection.connecting);
        for connection in state.connections.values_mut() {
            connection.gone = true;
        }
    }

    /// The host answers a connection the guest asked for.
    fn answer(&self, id: ConnectionId) {
        self.with(id, |connection| {
            connection.connecting = false;
            connection.live = true;
        });
    }

    /// The host refuses a connection the guest asked for, which the device
    /// forgets.
    fn refuse_connect(&self, id: ConnectionId) {
        self.0.lock().connections.remove(&id);
    }

    fn with<T>(&self, id: ConnectionId, f: impl FnOnce(&mut HostConnection) -> T) -> T {
        f(self.0.lock().connections.get_mut(&id).unwrap())
    }

    /// The host sends `bytes`; the device drops them once the guest shut
    /// down receiving.
    fn send(&self, id: ConnectionId, bytes: &[u8]) {
        self.with(id, |connection| {
            if !connection.shut_down_receiving {
                connection.sent.extend(bytes);
            }
        });
    }

    fn take_received(&self, id: ConnectionId) -> Vec<u8> {
        self.with(id, |connection| core::mem::take(&mut connection.received))
    }

    fn exists(&self, id: ConnectionId) -> bool {
        self.0.lock().connections.contains_key(&id)
    }

    fn take_forgotten(&self) -> Vec<(ConnectionId, bool)> {
        core::mem::take(&mut self.0.lock().forgotten)
    }

    fn take_refused(&self) -> Vec<ConnectionId> {
        core::mem::take(&mut self.0.lock().refused)
    }

    fn asked(&self) -> Vec<ConnectionId> {
        self.0.lock().asked.clone()
    }
}

impl Vsock for Host {
    fn guest_cid(&self) -> u64 {
        self.0.lock().guest_cid
    }

    fn take_request(&self) -> Option<ConnectionId> {
        self.0.lock().requests.pop_front()
    }

    fn accept(&self, id: ConnectionId) -> bool {
        self.with(id, |connection| {
            connection.live = !connection.gone;
            connection.live
        })
    }

    fn refuse(&self, id: ConnectionId) {
        let mut state = self.0.lock();
        state.connections.remove(&id);
        state.refused.push(id);
    }

    fn connect(&self, id: ConnectionId) -> bool {
        let mut state = self.0.lock();
        let by_guest = state
            .connections
            .values()
            .filter(|connection| connection.by_guest)
            .count();
        if by_guest >= MAX_USER_CONNECTIONS || state.connections.contains_key(&id) {
            return false;
        }
        state.asked.push(id);
        state.connections.insert(
            id,
            HostConnection {
                by_guest: true,
                connecting: true,
                credit: usize::MAX,
                ..HostConnection::default()
            },
        );
        true
    }

    fn connect_state(&self, id: ConnectionId) -> ConnectState {
        match self.0.lock().connections.get(&id) {
            Some(connection) if connection.by_guest && connection.connecting => {
                ConnectState::Connecting
            }
            Some(connection) if connection.by_guest && connection.live => ConnectState::Established,
            _ => ConnectState::Failed,
        }
    }

    fn read(&self, id: ConnectionId, output: &mut [u8]) -> Option<usize> {
        let mut state = self.0.lock();
        let connection = state.connections.get_mut(&id)?;
        if connection.sent.is_empty() {
            let ended = connection.gone || connection.sent_all || connection.shut_down_receiving;
            return (!ended).then_some(0);
        }
        let len = output.len().min(connection.sent.len());
        for (byte, sent) in output.iter_mut().zip(connection.sent.drain(..len)) {
            *byte = sent;
        }
        Some(len)
    }

    fn write(&self, id: ConnectionId, bytes: &[u8]) -> Option<usize> {
        let mut state = self.0.lock();
        let connection = state.connections.get_mut(&id)?;
        if connection.takes_no_more() {
            return None;
        }
        let len = bytes.len().min(connection.credit);
        connection.received.extend_from_slice(&bytes[..len]);
        connection.credit -= len;
        Some(len)
    }

    fn status(&self, id: ConnectionId) -> ConnectionStatus {
        match self.0.lock().connections.get(&id) {
            None => ConnectionStatus::ENDED,
            Some(connection) => ConnectionStatus {
                readable: !connection.sent.is_empty(),
                host_sending_ended: connection.gone || connection.sent_all,
                writable: connection.takes_no_more() || connection.credit > 0,
            },
        }
    }

    fn shutdown_sending(&self, id: ConnectionId) {
        self.with(id, |connection| connection.shut_down_sending = true);
    }

    fn shutdown_receiving(&self, id: ConnectionId) {
        self.with(id, |connection| connection.shut_down_receiving = true);
    }

    fn close(&self, id: ConnectionId) {
        self.with(id, |connection| {
            connection.shut_down_sending = true;
            connection.shut_down_receiving = true;
        });
    }

    fn is_closed(&self, id: ConnectionId) -> bool {
        self.0
            .lock()
            .connections
            .get(&id)
            .is_none_or(|connection| connection.gone && connection.sent.is_empty())
    }

    fn forget(&self, id: ConnectionId) {
        let mut state = self.0.lock();
        let gone = state
            .connections
            .remove(&id)
            .is_none_or(|connection| connection.gone);
        state.forgotten.push((id, !gone));
    }

    fn take_backlog(&self) -> bool {
        core::mem::take(&mut self.0.lock().backlog)
    }

    fn interrupts(&self) -> bool {
        true
    }
}

/// Every readiness publication, by handle.
#[derive(Default)]
struct Sink(spin::Mutex<Vec<(ObjectHandle, ReadinessFlags)>>);

impl ReadinessSink for Sink {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.0.lock().push((handle, readiness));
        Ok(())
    }

    fn republish(&self, handle: ObjectHandle, readiness: ReadinessFlags) -> Result<()> {
        self.publish(handle, readiness)
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

/// The provider in a broker core, the host behind its device, and a guest
/// process.
struct Fixture {
    provider: Arc<VsockDeviceProvider<TestInstant>>,
    host: Arc<Host>,
    guest: Arc<BrokerProcess>,
    sink: Arc<Sink>,
    clock: Arc<AtomicU64>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_seed(SEED.into())
    }

    fn with_seed(seed: u64) -> Self {
        let host = Host::new();
        let clock = Arc::new(AtomicU64::new(1));
        let now = Arc::clone(&clock);
        let provider = Arc::new(VsockDeviceProvider::new(
            host.clone(),
            Box::new(move || TestInstant(now.load(Ordering::SeqCst))),
            seed,
        ));
        // As the VM broker's.
        let core = TestBrokerCoreBuilder::new(
            PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
                .with_vsock_policy(VsockPolicy::any()),
        )
        .with_vsock_provider(provider.clone())
        .build()
        .unwrap();
        let guest = core
            .create_process(CallerCredential::HostGuaranteed, None)
            .unwrap();
        Self {
            provider,
            host,
            guest,
            sink: Arc::default(),
            clock,
        }
    }

    fn now(&self) -> TestInstant {
        TestInstant(self.clock.load(Ordering::SeqCst))
    }

    fn advance(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap();
        self.clock.fetch_add(nanos, Ordering::SeqCst);
    }

    fn poll(&self) {
        self.provider.poll();
    }

    fn socket(&self) -> ObjectHandle {
        core_vsock::create(&self.guest, FileOpenFlags::NONBLOCKING, self.sink.clone()).unwrap()
    }

    fn bind(&self, socket: ObjectHandle, cid: u32, port: u32) -> SocketOutcome<()> {
        core_vsock::bind(&self.guest, socket, VsockAddress { cid, port }).unwrap()
    }

    /// A socket listening on `port`.
    fn listen(&self, port: u32, backlog: u32) -> ObjectHandle {
        let listener = self.socket();
        assert_eq!(
            self.bind(listener, VMADDR_CID_ANY, port),
            SocketOutcome::Completed(())
        );
        assert_eq!(
            core_vsock::listen(&self.guest, listener, backlog).unwrap(),
            SocketOutcome::Completed(())
        );
        listener
    }

    fn accept(&self, listener: ObjectHandle) -> Result<AcceptedVsockSocket> {
        core_vsock::accept(
            &self.guest,
            listener,
            FileOpenFlags::NONBLOCKING,
            self.sink.clone(),
        )
        .map(|accepted| match accepted {
            SocketOutcome::Completed(accepted) => accepted,
            SocketOutcome::Failed(error) => panic!("accept: {error:?}"),
        })
    }

    /// A socket the host connected to `listener` from `host_port`, accepted.
    fn accepted(&self, listener: ObjectHandle, host_port: u32) -> ObjectHandle {
        self.host.connect(on(host_port));
        self.poll();
        self.accept(listener).unwrap().handle
    }

    fn connect(&self, socket: ObjectHandle, port: u32) -> SocketOutcome<SocketConnectionStatus> {
        let address = VsockAddress {
            cid: VMADDR_CID_HOST,
            port,
        };
        core_vsock::connect(&self.guest, socket, address).unwrap()
    }

    /// A socket connected to the host's `port`, from the returned connection.
    fn connected(&self, port: u32) -> (ObjectHandle, ConnectionId) {
        let socket = self.socket();
        assert_eq!(
            self.connect(socket, port),
            SocketOutcome::Completed(SocketConnectionStatus::Connecting)
        );
        let connection = id(self.local(socket).unwrap().port, port);
        self.host.answer(connection);
        self.poll();
        (socket, connection)
    }

    fn check_connect(&self, socket: ObjectHandle) -> SocketOutcome<SocketConnectionStatus> {
        core_vsock::check_connect(&self.guest, socket).unwrap()
    }

    fn cancel_connect(&self, socket: ObjectHandle) -> SocketOutcome<()> {
        core_vsock::cancel_connect(&self.guest, socket).unwrap()
    }

    fn take_error(&self, socket: ObjectHandle) -> Option<SocketError> {
        core_vsock::take_error(&self.guest, socket).unwrap()
    }

    fn send(&self, socket: ObjectHandle, bytes: &[u8]) -> Result<SocketOutcome<usize>> {
        core_vsock::send(&self.guest, socket, &bytes, SendFlags::NONE)
    }

    /// Receives up to `len` bytes: `None` at the end of the stream.
    fn receive(&self, socket: ObjectHandle, len: usize) -> Result<SocketOutcome<Option<Vec<u8>>>> {
        let mut buffer = vec![0; len];
        Ok(
            match core_vsock::receive(&self.guest, socket, &mut buffer, ReceiveFlags::NONE)? {
                SocketOutcome::Completed(PlatformStreamReceive::Received(received)) => {
                    buffer.truncate(received);
                    SocketOutcome::Completed(Some(buffer))
                }
                SocketOutcome::Completed(PlatformStreamReceive::EndOfStream) => {
                    SocketOutcome::Completed(None)
                }
                SocketOutcome::Failed(error) => SocketOutcome::Failed(error),
            },
        )
    }

    fn received(&self, socket: ObjectHandle, len: usize) -> Option<Vec<u8>> {
        match self.receive(socket, len).unwrap() {
            SocketOutcome::Completed(received) => received,
            SocketOutcome::Failed(error) => panic!("receive: {error:?}"),
        }
    }

    fn shutdown(&self, socket: ObjectHandle, mode: ShutdownMode) -> SocketOutcome<()> {
        core_vsock::shutdown(&self.guest, socket, mode).unwrap()
    }

    fn local(&self, socket: ObjectHandle) -> Option<VsockAddress> {
        core_vsock::get_name(&self.guest, socket, false).unwrap()
    }

    fn peer(&self, socket: ObjectHandle) -> Option<VsockAddress> {
        core_vsock::get_name(&self.guest, socket, true).unwrap()
    }

    fn readiness(&self, socket: ObjectHandle) -> ReadinessFlags {
        self.guest.check_readiness(socket).unwrap()
    }

    /// Takes the readiness published for `socket`.
    fn published(&self, socket: ObjectHandle) -> Vec<ReadinessFlags> {
        let mut published = self.sink.0.lock();
        let (taken, kept) = published
            .drain(..)
            .partition(|(handle, _)| *handle == socket);
        *published = kept;
        taken.into_iter().map(|(_, flags)| flags).collect()
    }

    fn close(&self, socket: ObjectHandle) {
        self.guest.close_object_reference(socket).unwrap();
    }
}

fn host(port: u32) -> VsockAddress {
    VsockAddress {
        cid: VMADDR_CID_HOST,
        port,
    }
}

#[test]
fn requests_go_to_listeners_with_room_and_are_refused_otherwise() {
    let f = Fixture::new();
    // One more than the backlog waits, as on Linux.
    let listener = f.listen(PORT, 1);
    let bound = f.socket();
    assert_eq!(
        f.bind(bound, VMADDR_CID_ANY, PORT + 1),
        SocketOutcome::Completed(())
    );
    assert_eq!(f.published(listener), [WRITE, NONE]);
    for request in [id(PORT + 1, 1), id(PORT + 2, 2), on(3), on(4), on(5)] {
        f.host.connect(request);
    }
    f.poll();
    assert_eq!(
        f.host.take_refused(),
        [id(PORT + 1, 1), id(PORT + 2, 2), on(5)]
    );
    assert!(f.host.with(on(3), |connection| connection.live));
    assert_eq!(f.published(listener), [READ]);
    let accepted = f.accept(listener).unwrap();
    assert_eq!(accepted.peer_address, host(3));
    assert_eq!(
        f.local(accepted.handle),
        Some(VsockAddress {
            cid: GUEST_CID,
            port: PORT
        })
    );
    assert_eq!(f.peer(accepted.handle), Some(host(3)));
    assert_eq!(f.published(accepted.handle), [WRITE]);
    assert_eq!(f.readiness(listener), READ);
    assert_eq!(f.accept(listener).unwrap().peer_address, host(4));
    assert_eq!(f.published(listener), [NONE]);
    assert_eq!(
        f.accept(listener).err(),
        Some(BrokerError::NonBlockingWouldBlock)
    );
    // Room again; a listener that listens again keeps its backlog.
    f.host.connect(on(6));
    f.host.connect(on(7));
    f.poll();
    assert_eq!(
        core_vsock::listen(&f.guest, listener, 0).unwrap(),
        SocketOutcome::Completed(())
    );
    f.host.connect(on(8));
    f.poll();
    assert_eq!(f.host.take_refused(), [on(8)]);
    assert_eq!(f.accept(listener).unwrap().peer_address, host(6));
    assert_eq!(f.accept(listener).unwrap().peer_address, host(7));
}

#[test]
fn requests_are_answered_a_few_per_poll() {
    let f = Fixture::new();
    for host_port in 0..20 {
        f.host.connect(on(host_port));
    }
    f.poll();
    assert_eq!(f.host.take_refused().len(), MAX_REQUESTS_PER_POLL);
    assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
    f.poll();
    f.poll();
    assert_eq!(f.host.take_refused().len(), 20 - MAX_REQUESTS_PER_POLL);
    f.poll();
    assert_eq!(f.provider.next_deadline(), None);
    // An operation that left the device with a backlog has a poll due.
    let socket = f.socket();
    f.host.0.lock().backlog = true;
    assert_eq!(
        f.bind(socket, VMADDR_CID_ANY, PORT),
        SocketOutcome::Completed(())
    );
    assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
    f.poll();
    assert_eq!(f.provider.next_deadline(), None);
    // So has closing a connecting socket, whose connect the device forgets.
    let connecting = f.socket();
    assert_eq!(
        f.connect(connecting, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    f.host.0.lock().backlog = true;
    f.close(connecting);
    assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
    f.poll();
    assert_eq!(f.provider.next_deadline(), None);
}

#[test]
fn data_moves_straight_to_and_from_the_device_with_backpressure() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let socket = f.accepted(listener, 7);
    assert_eq!(f.published(socket), [WRITE]);
    // Nothing queued.
    assert_eq!(
        f.receive(socket, 16).err(),
        Some(BrokerError::NonBlockingWouldBlock)
    );
    f.host.send(on(7), b"ping");
    f.poll();
    assert_eq!(f.published(socket), [READ | WRITE]);
    assert_eq!(f.received(socket, 2), Some(b"pi".to_vec()));
    assert_eq!(f.published(socket), []);
    assert_eq!(f.received(socket, 16), Some(b"ng".to_vec()));
    assert_eq!(f.published(socket), [WRITE]);
    // More than a staging chunk each way.
    let bulk: Vec<u8> = (0..3 * STAGE + 5)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    f.host.send(on(7), &bulk);
    assert_eq!(f.received(socket, bulk.len() + 1), Some(bulk.clone()));
    assert_eq!(
        f.send(socket, &bulk),
        Ok(SocketOutcome::Completed(bulk.len()))
    );
    assert_eq!(f.host.take_received(on(7)), bulk);
    // The host's credit runs out: a partial send, then none, until it gives
    // more.
    f.host.with(on(7), |connection| connection.credit = 5);
    assert_eq!(
        f.send(socket, b"pong pong"),
        Ok(SocketOutcome::Completed(5))
    );
    assert_eq!(f.published(socket), [NONE]);
    assert_eq!(
        f.send(socket, b"pong"),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    f.poll();
    assert_eq!(f.published(socket), []);
    f.host.with(on(7), |connection| connection.credit = 100);
    f.poll();
    assert_eq!(f.published(socket), [WRITE]);
    assert_eq!(f.send(socket, b"pong"), Ok(SocketOutcome::Completed(4)));
    assert_eq!(f.host.take_received(on(7)), b"pong pong");
    // Empty transfers check the state only.
    assert_eq!(f.send(socket, b""), Ok(SocketOutcome::Completed(0)));
    assert_eq!(
        f.receive(socket, 0),
        Ok(SocketOutcome::Completed(Some(Vec::new())))
    );
    let unconnected = f.socket();
    assert_eq!(
        f.send(unconnected, b""),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    assert_eq!(
        f.receive(unconnected, 0),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
}

#[test]
fn the_hosts_shutdowns_end_each_direction() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let socket = f.accepted(listener, 7);
    // The host sends no more: its data is read first.
    f.host.send(on(7), b"bye");
    f.host.with(on(7), |connection| connection.sent_all = true);
    f.poll();
    assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
    assert_eq!(f.received(socket, 16), Some(b"bye".to_vec()));
    assert_eq!(f.received(socket, 16), None);
    // The guest still sends; once it shuts down sending too, both ways are
    // down.
    assert_eq!(f.send(socket, b"ok"), Ok(SocketOutcome::Completed(2)));
    assert_eq!(
        f.shutdown(socket, ShutdownMode::Write),
        SocketOutcome::Completed(())
    );
    assert!(
        f.host
            .with(on(7), |connection| connection.shut_down_sending)
    );
    assert_eq!(f.readiness(socket), READ | HANGUP | CLOSED);
    assert_eq!(
        f.send(socket, b"more"),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    // The host receives no more: sends fail, rather than wait.
    let socket = f.accepted(listener, 8);
    f.host.with(on(8), |connection| {
        connection.receives_no_more = true;
        connection.credit = 0;
    });
    f.poll();
    assert_eq!(f.readiness(socket), WRITE);
    assert_eq!(
        f.send(socket, b"x"),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    // Its reset ends the stream after its data; then the device forgets it.
    f.host.send(on(8), b"last");
    f.host.with(on(8), |connection| connection.gone = true);
    f.poll();
    assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
    assert_eq!(f.host.take_forgotten(), []);
    assert_eq!(f.received(socket, 16), Some(b"last".to_vec()));
    f.poll();
    assert_eq!(f.host.take_forgotten(), [(on(8), false)]);
    assert_eq!(f.received(socket, 16), None);
    assert_eq!(
        f.send(socket, b"x"),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    assert_eq!(f.peer(socket), Some(host(8)));
    assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
}

#[test]
fn the_guests_shutdowns_end_each_direction() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    // Shutting down receiving drops what is queued and what comes; sends
    // go on.
    let socket = f.accepted(listener, 7);
    f.host.send(on(7), b"queued");
    assert_eq!(
        f.shutdown(socket, ShutdownMode::Read),
        SocketOutcome::Completed(())
    );
    assert!(
        f.host
            .with(on(7), |connection| connection.shut_down_receiving)
    );
    assert_eq!(f.readiness(socket), READ | HANGUP | WRITE);
    assert_eq!(f.received(socket, 16), None);
    f.poll();
    assert!(f.host.with(on(7), |connection| connection.sent.is_empty()));
    assert_eq!(f.send(socket, b"reply"), Ok(SocketOutcome::Completed(5)));
    assert_eq!(f.host.take_received(on(7)), b"reply");
    // A shut-down socket has no peer, and does not connect, as on Linux.
    assert_eq!(f.peer(socket), None);
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Failed(SocketError::InvalidArgument)
    );
    // Both ways: the host is told at once.
    let socket = f.accepted(listener, 8);
    assert_eq!(
        f.shutdown(socket, ShutdownMode::Both),
        SocketOutcome::Completed(())
    );
    f.host.with(on(8), |connection| {
        assert!(connection.shut_down_sending && connection.shut_down_receiving);
    });
    assert_eq!(f.readiness(socket), READ | HANGUP | CLOSED);
    // Only connected sockets shut down.
    for socket in [f.socket(), listener] {
        assert_eq!(
            f.shutdown(socket, ShutdownMode::Both),
            SocketOutcome::Failed(SocketError::NotConnected)
        );
    }
}

#[test]
fn closed_connections_linger_until_the_host_resets_them() {
    let f = Fixture::new();
    let (socket, connection) = f.connected(5000);
    f.host.with(connection, |connection| connection.credit = 0);
    assert_eq!(
        f.send(socket, b"reply"),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    f.close(socket);
    f.host.with(connection, |connection| {
        assert!(connection.shut_down_sending && connection.shut_down_receiving);
    });
    // Its port stays in use meanwhile.
    let other = f.socket();
    assert_eq!(
        f.bind(other, VMADDR_CID_ANY, connection.guest_port),
        SocketOutcome::Failed(SocketError::AddressInUse)
    );
    f.poll();
    assert_eq!(f.provider.next_deadline(), after(f.now(), CLOSE_TIMEOUT));
    // What the host sent before it knew is dropped.
    f.host.with(connection, |connection| {
        connection.sent.extend(b"late");
        connection.gone = true;
    });
    f.poll();
    assert_eq!(f.host.take_forgotten(), [(connection, false)]);
    assert_eq!(f.provider.next_deadline(), None);
    assert_eq!(
        f.bind(other, VMADDR_CID_ANY, connection.guest_port),
        SocketOutcome::Completed(())
    );
}

#[test]
fn closed_connections_are_reset_after_the_close_timeout() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let socket = f.accepted(listener, 7);
    f.close(socket);
    f.poll();
    let timeout = after(f.now(), CLOSE_TIMEOUT);
    assert_eq!(f.provider.next_deadline(), timeout);
    f.advance(CLOSE_TIMEOUT.checked_sub(Duration::from_nanos(1)).unwrap());
    f.poll();
    assert_eq!(f.host.take_forgotten(), []);
    f.advance(Duration::from_nanos(1));
    f.poll();
    assert_eq!(f.host.take_forgotten(), [(on(7), true)]);
    assert_eq!(f.provider.next_deadline(), None);
}

#[test]
fn closed_accepted_connections_leave_the_port_to_the_listener() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let socket = f.accepted(listener, 7);
    f.close(socket);
    f.host.connect(on(8));
    f.poll();
    assert_eq!(f.accept(listener).unwrap().peer_address, host(8));
    f.close(listener);
    // Free, although the connection still lingers on it.
    let listener = f.listen(PORT, 4);
    assert!(
        f.host
            .with(on(7), |connection| connection.shut_down_sending)
    );
    assert_eq!(f.host.take_forgotten(), []);
    f.host.connect(on(9));
    f.poll();
    assert_eq!(f.accept(listener).unwrap().peer_address, host(9));
}

#[test]
fn retired_listeners_close_their_backlogs_and_free_their_ports() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let accepted = f.accepted(listener, 1);
    f.host.connect(on(2));
    f.host.connect(on(3));
    f.poll();
    f.close(listener);
    // Closed as a connected socket is, lingering until the host resets them.
    for connection in [on(2), on(3)] {
        f.host.with(connection, |connection| {
            assert!(connection.shut_down_sending && connection.shut_down_receiving);
        });
    }
    assert_eq!(f.host.take_forgotten(), []);
    assert_eq!(f.provider.next_deadline(), after(f.now(), BUSY_INTERVAL));
    // The accepted connection goes on; the port is free.
    assert_eq!(f.send(accepted, b"x"), Ok(SocketOutcome::Completed(1)));
    let listener = f.listen(PORT, 4);
    f.host.connect(on(4));
    f.poll();
    assert_eq!(f.accept(listener).unwrap().peer_address, host(4));
    assert_eq!(f.host.take_refused(), []);
    f.host.with(on(2), |connection| connection.gone = true);
    f.poll();
    assert_eq!(f.host.take_forgotten(), [(on(2), false)]);
    f.advance(CLOSE_TIMEOUT);
    f.poll();
    assert_eq!(f.host.take_forgotten(), [(on(3), true)]);
}

#[test]
fn connects_reach_the_host_and_complete_on_its_answer() {
    let f = Fixture::new();
    let socket = f.socket();
    assert_eq!(f.published(socket), [WRITE]);
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    // Bound to an ephemeral port, for any CID.
    assert_eq!(
        f.local(socket),
        Some(VsockAddress {
            cid: VMADDR_CID_ANY,
            port: SEED
        })
    );
    let connection = id(SEED, 5000);
    assert_eq!(f.host.asked(), [connection]);
    assert_eq!(f.published(socket), [NONE]);
    assert_eq!(f.peer(socket), None);
    assert_eq!(
        f.send(socket, b"x"),
        Ok(SocketOutcome::Failed(SocketError::NotConnected))
    );
    // Found in progress.
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Failed(SocketError::AlreadyInProgress)
    );
    assert_eq!(
        f.check_connect(socket),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    f.poll();
    assert_eq!(f.provider.next_deadline(), after(f.now(), CONNECT_TIMEOUT));
    // Without credit, the connected socket is no more ready than the
    // connecting one: the change is republished.
    f.host.answer(connection);
    f.host.with(connection, |connection| connection.credit = 0);
    f.poll();
    assert_eq!(f.published(socket), [NONE]);
    assert_eq!(
        f.check_connect(socket),
        SocketOutcome::Completed(SocketConnectionStatus::Connected)
    );
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Failed(SocketError::AlreadyConnected)
    );
    assert_eq!(f.peer(socket), Some(host(5000)));
    assert_eq!(f.provider.next_deadline(), None);
    f.host
        .with(connection, |connection| connection.credit = 100);
    f.host.send(connection, b"pong");
    f.poll();
    assert_eq!(f.published(socket), [READ | WRITE]);
    assert_eq!(f.send(socket, b"ping"), Ok(SocketOutcome::Completed(4)));
    assert_eq!(f.host.take_received(connection), b"ping");
    assert_eq!(f.received(socket, 16), Some(b"pong".to_vec()));
}

#[test]
fn connects_check_their_state_then_the_address() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    assert_eq!(
        f.connect(listener, 5000),
        SocketOutcome::Failed(SocketError::InvalidArgument)
    );
    assert_eq!(
        f.check_connect(listener),
        SocketOutcome::Failed(SocketError::InvalidArgument)
    );
    let socket = f.socket();
    let address = VsockAddress {
        cid: GUEST_CID,
        port: 5000,
    };
    assert_eq!(
        core_vsock::connect(&f.guest, socket, address).unwrap(),
        SocketOutcome::Failed(SocketError::NetworkUnreachable)
    );
    // Unbound still.
    assert_eq!(f.local(socket), None);
    assert_eq!(
        f.check_connect(socket),
        SocketOutcome::Completed(SocketConnectionStatus::Unconnected)
    );
    assert_eq!(f.cancel_connect(socket), SocketOutcome::Completed(()));
    // A bound socket connects from its port.
    let bound = f.socket();
    assert_eq!(f.bind(bound, GUEST_CID, 4000), SocketOutcome::Completed(()));
    assert_eq!(
        f.connect(bound, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    assert_eq!(f.host.asked(), [id(4000, 5000)]);
}

#[test]
fn refused_connects_leave_a_pending_error() {
    let f = Fixture::new();
    let socket = f.socket();
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    let connection = id(SEED, 5000);
    f.poll();
    f.published(socket);
    f.host.refuse_connect(connection);
    f.poll();
    assert_eq!(f.published(socket), [WRITE | ERROR]);
    assert_eq!(f.host.take_forgotten(), [(connection, false)]);
    // Checks, and connects to an address that is not the host's, leave it
    // pending; the next connect takes it.
    for _ in 0..2 {
        assert_eq!(
            f.check_connect(socket),
            SocketOutcome::Failed(SocketError::ConnectionReset)
        );
    }
    for cid in [GUEST_CID, VMADDR_CID_ANY] {
        let address = VsockAddress { cid, port: 5000 };
        assert_eq!(
            core_vsock::connect(&f.guest, socket, address).unwrap(),
            SocketOutcome::Failed(SocketError::NetworkUnreachable)
        );
    }
    assert_eq!(f.readiness(socket), WRITE | ERROR);
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Failed(SocketError::ConnectionReset)
    );
    assert_eq!(f.readiness(socket), WRITE);
    // From the same port.
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    f.host.refuse_connect(connection);
    // Seen without a poll.
    assert_eq!(f.take_error(socket), Some(SocketError::ConnectionReset));
    assert_eq!(f.take_error(socket), None);
    assert_eq!(f.readiness(socket), WRITE);
    assert_eq!(f.host.asked(), [connection, connection]);
}

#[test]
fn connects_the_host_does_not_answer_time_out() {
    let f = Fixture::new();
    let socket = f.socket();
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    let connection = id(SEED, 5000);
    f.advance(
        CONNECT_TIMEOUT
            .checked_sub(Duration::from_nanos(1))
            .unwrap(),
    );
    f.poll();
    assert_eq!(f.host.take_forgotten(), []);
    f.advance(Duration::from_nanos(1));
    f.poll();
    assert_eq!(f.readiness(socket), WRITE | ERROR);
    assert_eq!(f.host.take_forgotten(), [(connection, true)]);
    assert_eq!(f.provider.next_deadline(), None);
    // A blocking connect's check takes it.
    assert_eq!(
        f.check_connect(socket),
        SocketOutcome::Failed(SocketError::TimedOut)
    );
    assert_eq!(
        f.check_connect(socket),
        SocketOutcome::Completed(SocketConnectionStatus::Unconnected)
    );
    assert_eq!(f.readiness(socket), WRITE);
}

#[test]
fn cancelled_connects_end_the_attempt() {
    let f = Fixture::new();
    let socket = f.socket();
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    let connection = id(SEED, 5000);
    assert_eq!(f.cancel_connect(socket), SocketOutcome::Completed(()));
    assert_eq!(f.host.take_forgotten(), [(connection, true)]);
    assert_eq!(f.readiness(socket), WRITE);
    assert_eq!(f.take_error(socket), None);
    assert_eq!(f.local(socket).unwrap().port, SEED);
    assert_eq!(f.provider.next_deadline(), None);
    // Connected meanwhile: the connect stands.
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    f.host.answer(connection);
    assert_eq!(
        f.cancel_connect(socket),
        SocketOutcome::Failed(SocketError::AlreadyConnected)
    );
    assert_eq!(f.send(socket, b"x"), Ok(SocketOutcome::Completed(1)));
    // Failed meanwhile: its error.
    let socket = f.socket();
    assert_eq!(
        f.connect(socket, 5001),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    f.host.refuse_connect(id(SEED + 1, 5001));
    assert_eq!(
        f.cancel_connect(socket),
        SocketOutcome::Failed(SocketError::ConnectionReset)
    );
    // Closing a connecting socket cancels it.
    let socket = f.socket();
    assert_eq!(
        f.connect(socket, 5002),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    f.close(socket);
    assert_eq!(
        f.host.take_forgotten(),
        [(id(SEED + 1, 5001), false), (id(SEED + 2, 5002), true)]
    );
}

#[test]
fn connects_beyond_the_guests_share_of_the_device_fail() {
    let f = Fixture::new();
    let sockets: Vec<_> = (0..MAX_USER_CONNECTIONS)
        .map(|_| f.connected(5000).0)
        .collect();
    let socket = f.socket();
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Failed(SocketError::ConnectionReset)
    );
    // Bound, unconnected, without an error.
    assert_eq!(f.readiness(socket), WRITE);
    assert!(f.local(socket).is_some());
    // The host's requests still get through.
    let listener = f.listen(PORT, 4);
    let accepted = f.accepted(listener, 6000);
    assert_eq!(f.send(accepted, b"x"), Ok(SocketOutcome::Completed(1)));
    // A guest connection ends: room again.
    f.close(sockets[0]);
    let connection = id(SEED, 5000);
    f.host.with(connection, |connection| connection.gone = true);
    f.poll();
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
}

#[test]
fn host_requests_on_a_connects_connection_are_refused() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let socket = f.socket();
    assert_eq!(
        f.bind(socket, VMADDR_CID_ANY, PORT + 1),
        SocketOutcome::Completed(())
    );
    assert_eq!(
        f.connect(socket, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    let connection = id(PORT + 1, 5000);
    // The host refuses the connect, and requests the same connection before
    // the provider sees the refusal.
    f.host.refuse_connect(connection);
    f.host.connect(connection);
    f.poll();
    assert_eq!(f.host.take_refused(), [connection]);
    assert_eq!(f.take_error(socket), Some(SocketError::ConnectionReset));
    assert!(!f.host.exists(connection));
    assert_eq!(
        f.accept(listener).err(),
        Some(BrokerError::NonBlockingWouldBlock)
    );
}

#[test]
fn a_transport_reset_fails_connects_and_ends_connections() {
    let f = Fixture::new();
    let listener = f.listen(PORT, 4);
    let accepted = f.accepted(listener, 7);
    f.host.send(on(7), b"last");
    let connecting = f.socket();
    assert_eq!(
        f.connect(connecting, 5000),
        SocketOutcome::Completed(SocketConnectionStatus::Connecting)
    );
    f.host.reset_all();
    f.poll();
    assert_eq!(f.take_error(connecting), Some(SocketError::ConnectionReset));
    assert_eq!(f.received(accepted, 16), Some(b"last".to_vec()));
    assert_eq!(f.received(accepted, 16), None);
    assert_eq!(
        f.send(accepted, b"lost"),
        Ok(SocketOutcome::Failed(SocketError::Shutdown))
    );
    f.poll();
    assert_eq!(
        f.host.take_forgotten(),
        [(id(SEED, 5000), false), (on(7), false)]
    );
}

#[test]
fn binds_take_the_guests_cids_and_unused_ports() {
    let f = Fixture::new();
    let socket = f.socket();
    assert_eq!(
        f.bind(socket, GUEST_CID + 1, PORT),
        SocketOutcome::Failed(SocketError::AddressNotAvailable)
    );
    assert_eq!(f.local(socket), None);
    assert_eq!(
        f.bind(socket, GUEST_CID, PORT),
        SocketOutcome::Completed(())
    );
    assert_eq!(
        f.local(socket),
        Some(VsockAddress {
            cid: GUEST_CID,
            port: PORT
        })
    );
    assert_eq!(
        f.bind(socket, VMADDR_CID_ANY, PORT + 1),
        SocketOutcome::Failed(SocketError::InvalidArgument)
    );
    let other = f.socket();
    assert_eq!(
        f.bind(other, VMADDR_CID_ANY, PORT),
        SocketOutcome::Failed(SocketError::AddressInUse)
    );
    // Listening needs a bound, unconnected socket.
    assert_eq!(
        core_vsock::listen(&f.guest, other, 1).unwrap(),
        SocketOutcome::Failed(SocketError::InvalidArgument)
    );
    // Freed as its socket closes.
    f.close(socket);
    assert_eq!(
        f.bind(other, VMADDR_CID_ANY, PORT),
        SocketOutcome::Completed(())
    );
}

/// The port an ephemeral bind of a new socket takes, if any.
fn ephemeral(f: &Fixture) -> Option<u32> {
    let socket = f.socket();
    match f.bind(socket, VMADDR_CID_ANY, VMADDR_PORT_ANY) {
        SocketOutcome::Completed(()) => Some(f.local(socket).unwrap().port),
        SocketOutcome::Failed(error) => {
            assert_eq!(error, SocketError::AddressNotAvailable);
            None
        }
    }
}

#[test]
fn ephemeral_ports_follow_the_seed_and_skip_those_in_use() {
    let f = Fixture::new();
    assert_eq!(ephemeral(&f), Some(SEED));
    let taken = f.socket();
    assert_eq!(
        f.bind(taken, VMADDR_CID_ANY, SEED + 1),
        SocketOutcome::Completed(())
    );
    assert_eq!(ephemeral(&f), Some(SEED + 2));
    // A bounded search.
    let tries = u32::try_from(MAX_EPHEMERAL_TRIES).unwrap();
    for port in SEED + 3..SEED + 3 + tries {
        assert_eq!(
            f.bind(f.socket(), VMADDR_CID_ANY, port),
            SocketOutcome::Completed(())
        );
    }
    assert_eq!(ephemeral(&f), None);
    assert_eq!(ephemeral(&f), Some(SEED + 3 + tries));
}

#[test]
fn ephemeral_ports_wrap_above_the_reserved_ones() {
    let f = Fixture::with_seed(u64::from(u32::MAX - 1));
    assert_eq!(ephemeral(&f), Some(u32::MAX - 1));
    assert_eq!(ephemeral(&f), Some(LAST_RESERVED_PORT + 1));
}
