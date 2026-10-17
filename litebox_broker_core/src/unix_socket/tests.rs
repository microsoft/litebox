// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use crate::fs::in_mem::InMem;
use crate::fs::inode_allocator::InodeAllocator;
use crate::fs::resolver::Resolver;
use crate::readiness::tests::TestReadinessSink;
use crate::test_platform::TestPlatform;
use crate::test_support::TestBrokerCoreBuilder;
use crate::{BrokerCore, CallerCredential, PolicyEngine};
use std::vec;

const USER: FileUser = FileUser::ROOT;

struct Fixture {
    broker: BrokerCore,
    process: Arc<BrokerProcess>,
    sink: Arc<TestReadinessSink>,
    readiness_sink: Arc<dyn ReadinessSink>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_limits(BrokerCoreLimits::DEFAULT)
    }

    fn with_limits(limits: BrokerCoreLimits) -> Self {
        Self::build(limits, ObjectRights::all())
    }

    fn with_rights(rights: ObjectRights) -> Self {
        Self::build(BrokerCoreLimits::DEFAULT, rights)
    }

    fn build(limits: BrokerCoreLimits, rights: ObjectRights) -> Self {
        let fs = Resolver::<TestPlatform, _>::new(InMem::<TestPlatform>::new(
            InodeAllocator::standalone(),
        ));
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(rights))
            .with_limits(limits)
            .with_file_service(Arc::new(fs))
            .build()
            .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated, None)
            .unwrap();
        let sink = Arc::new(TestReadinessSink::default());
        Self {
            broker,
            process,
            readiness_sink: sink.clone(),
            sink,
        }
    }

    fn create(&self, socket_type: SocketType) -> ObjectHandle {
        create(
            &self.process,
            socket_type,
            FileOpenFlags::NONE,
            &self.readiness_sink,
        )
        .unwrap()
    }

    fn pair(&self, socket_type: SocketType) -> (ObjectHandle, ObjectHandle) {
        create_pair(
            &self.process,
            socket_type,
            FileOpenFlags::NONE,
            &self.readiness_sink,
        )
        .unwrap()
    }

    fn bind(&self, handle: ObjectHandle, address: &UnixSocketAddress) -> UnixSocketResult<()> {
        bind(&self.process, handle, address, USER, FileMode::RWXU).unwrap()
    }

    fn listener(&self, address: &UnixSocketAddress, backlog: u32) -> ObjectHandle {
        let listener = self.create(SocketType::Stream);
        self.bind(listener, address).unwrap();
        listen(&self.process, listener, backlog).unwrap().unwrap();
        listener
    }

    fn connect(
        &self,
        handle: ObjectHandle,
        address: &UnixSocketAddress,
    ) -> Result<UnixSocketResult<()>> {
        connect(&self.process, handle, address, USER)
    }

    fn accept(&self, listener: ObjectHandle) -> Result<UnixSocketResult<ObjectHandle>> {
        accept(
            &self.process,
            listener,
            FileOpenFlags::NONE,
            &self.readiness_sink,
        )
    }

    fn send(&self, handle: ObjectHandle, data: &[u8]) -> Result<UnixSocketResult<usize>> {
        send(&self.process, handle, None, data, USER)
    }

    fn send_to(
        &self,
        handle: ObjectHandle,
        address: &UnixSocketAddress,
        data: &[u8],
    ) -> Result<UnixSocketResult<usize>> {
        send(&self.process, handle, Some(address), data, USER)
    }

    fn receive(&self, handle: ObjectHandle, capacity: u32) -> Result<UnixSocketResult<Received>> {
        receive(&self.process, handle, capacity, false, true, false)
    }

    fn receive_data(&self, handle: ObjectHandle, capacity: u32) -> Vec<u8> {
        self.receive(handle, capacity).unwrap().unwrap().data
    }

    fn readiness(&self, handle: ObjectHandle) -> ReadinessFlags {
        self.process.check_readiness(handle).unwrap()
    }

    fn take_republished(&self) -> Vec<ObjectHandle> {
        core::mem::take(&mut *self.sink.republished.lock().unwrap())
            .into_iter()
            .map(|(handle, _)| handle)
            .collect()
    }

    fn close(&self, handle: ObjectHandle) {
        self.process.close_object_reference(handle).unwrap();
    }

    /// Returns the broker-wide and process charges for queued bytes.
    fn queued(&self) -> (usize, usize) {
        (
            *self.process.core.unix_sockets.queued.lock(),
            self.process.unix_socket_bytes.load(Ordering::Relaxed),
        )
    }

    /// Returns a weak reference to the socket behind `handle`.
    fn socket(&self, handle: ObjectHandle) -> Weak<Socket> {
        let object = self
            .process
            .authorized_object(handle, ObjectRights::WAIT)
            .unwrap();
        let entry = object.read();
        Arc::downgrade(&entry.as_unix_socket().unwrap().socket)
    }

    /// Repeats `operation` while it would block.
    fn retry<T>(operation: impl Fn() -> Result<T>) -> T {
        loop {
            match operation() {
                Err(BrokerError::WouldBlock) => std::thread::yield_now(),
                result => break result.unwrap(),
            }
        }
    }
}

fn path(path: &str) -> UnixSocketAddress {
    UnixSocketAddress::Path {
        path: path.into(),
        name: path.as_bytes().to_vec(),
    }
}

fn abstract_name(name: &[u8]) -> UnixSocketAddress {
    UnixSocketAddress::Abstract(name.to_vec())
}

#[test]
fn stream_pairs_carry_bytes_in_both_directions() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Stream);
    assert!(!fixture.readiness(second).contains(ReadinessFlags::READ));
    assert_eq!(fixture.send(first, b"hello").unwrap(), Ok(5));
    assert!(fixture.take_republished().contains(&second));
    assert!(fixture.readiness(second).contains(ReadinessFlags::READ));

    let peeked = receive(&fixture.process, second, 3, true, true, false)
        .unwrap()
        .unwrap();
    assert_eq!(peeked.data, b"hel");
    assert_eq!(peeked.source, Some(UnixSocketName::Unnamed));
    assert_eq!(fixture.receive_data(second, 3), b"hel");
    assert_eq!(fixture.receive_data(second, 10), b"lo");
    assert_eq!(fixture.receive(second, 10), Err(BrokerError::WouldBlock));
    assert_eq!(fixture.send(first, b""), Ok(Ok(0)));

    assert_eq!(fixture.send(second, b"back").unwrap(), Ok(4));
    assert_eq!(fixture.receive_data(first, 10), b"back");
    assert_eq!(fixture.queued(), (0, 0));
}

#[test]
fn path_listeners_accept_connections_with_names() {
    let fixture = Fixture::new();
    let address = path("/server");
    let listener = fixture.listener(&address, 8);
    assert_eq!(fixture.readiness(listener), ReadinessFlags::default());

    let client = fixture.create(SocketType::Stream);
    fixture.bind(client, &abstract_name(b"client")).unwrap();
    assert_eq!(fixture.accept(listener), Err(BrokerError::WouldBlock));
    assert_eq!(fixture.connect(client, &address).unwrap(), Ok(()));
    assert!(fixture.take_republished().contains(&listener));
    assert!(fixture.readiness(listener).contains(ReadinessFlags::READ));
    assert_eq!(
        fixture.connect(client, &address).unwrap(),
        Err(UnixSocketError::AlreadyConnected)
    );

    let server = fixture.accept(listener).unwrap().unwrap();
    assert_eq!(
        name(&fixture.process, server, false).unwrap(),
        Ok(address.name())
    );
    assert_eq!(
        name(&fixture.process, server, true).unwrap(),
        Ok(UnixSocketName::Abstract(b"client".to_vec()))
    );
    assert_eq!(
        name(&fixture.process, client, true).unwrap(),
        Ok(address.name())
    );
    assert_eq!(
        name(&fixture.process, listener, true).unwrap(),
        Err(UnixSocketError::NotConnected)
    );

    assert_eq!(fixture.send(client, b"ping").unwrap(), Ok(4));
    let received = fixture.receive(server, 16).unwrap().unwrap();
    assert_eq!(received.data, b"ping");
    assert_eq!(
        received.source,
        Some(UnixSocketName::Abstract(b"client".to_vec()))
    );
    assert_eq!(fixture.send(server, b"pong").unwrap(), Ok(4));
    assert_eq!(fixture.receive_data(client, 16), b"pong");
}

#[test]
fn path_names_stay_taken_until_unlinked() {
    let fixture = Fixture::new();
    let address = path("/server");
    let listener = fixture.listener(&address, 8);
    let other = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.bind(other, &address),
        Err(UnixSocketError::AddressInUse)
    );
    assert_eq!(
        fixture.bind(listener, &path("/again")),
        Err(UnixSocketError::InvalidArgument)
    );

    fixture.close(listener);
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect(client, &address).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
    assert_eq!(
        fixture.bind(other, &address),
        Err(UnixSocketError::AddressInUse)
    );
    crate::fs::unlink(&fixture.process, "/server", USER)
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture.connect(client, &address).unwrap(),
        Err(UnixSocketError::File(FileError::NoSuchFileOrDirectory))
    );
    assert_eq!(fixture.bind(other, &address), Ok(()));
    assert_eq!(
        fixture.connect(client, &path("/")).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
}

#[test]
fn abstract_names_are_released_on_close() {
    let fixture = Fixture::new();
    let address = abstract_name(b"name");
    let first = fixture.create(SocketType::Datagram);
    let second = fixture.create(SocketType::Datagram);
    assert_eq!(fixture.bind(first, &address), Ok(()));
    assert_eq!(
        fixture.bind(second, &address),
        Err(UnixSocketError::AddressInUse)
    );
    fixture.close(first);
    assert_eq!(fixture.bind(second, &address), Ok(()));
}

#[test]
fn abstract_names_are_held_per_socket_type() {
    let fixture = Fixture::new();
    let address = abstract_name(b"name");
    let datagram = fixture.create(SocketType::Datagram);
    assert_eq!(fixture.bind(datagram, &address), Ok(()));
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect(client, &address).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );

    let listener = fixture.listener(&address, 1);
    assert_eq!(fixture.connect(client, &address).unwrap(), Ok(()));
    assert!(fixture.accept(listener).unwrap().is_ok());
    let sender = fixture.create(SocketType::Datagram);
    assert_eq!(fixture.send_to(sender, &address, b"x").unwrap(), Ok(1));
    assert_eq!(fixture.receive_data(datagram, 1), b"x");
}

#[test]
fn path_connections_require_write_permission() {
    let fixture = Fixture::new();
    let address = path("/server");
    let listener = fixture.listener(&address, 1);
    let other = FileUser {
        user: 1000,
        group: 1000,
    };
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        connect(&fixture.process, client, &address, other).unwrap(),
        Err(UnixSocketError::File(FileError::AccessNotAllowed))
    );
    crate::fs::chmod(
        &fixture.process,
        "/server",
        USER,
        FileMode::RWXU | FileMode::WOTH,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        connect(&fixture.process, client, &address, other).unwrap(),
        Ok(())
    );
    assert!(fixture.accept(listener).unwrap().is_ok());

    let (file, _) = crate::fs::open_without_reference(
        &fixture.process,
        "/file",
        USER,
        FileAccessMode::WriteOnly,
        FileOpenFlags::CREATE,
        FileMode::RWXU,
    )
    .unwrap()
    .unwrap();
    drop(file);
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect(client, &path("/file")).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
}

#[test]
fn path_lookups_require_the_callers_file_rights() {
    // Write rights cover creating a path name, but looking one up needs the
    // rights of a path-only open.
    let fixture = Fixture::with_rights(ObjectRights::WRITE);
    let address = path("/server");
    fixture.listener(&address, 1);
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect(client, &address),
        Err(BrokerError::PolicyDenied)
    );
}

#[test]
fn unconnected_streams_reject_data_operations() {
    let fixture = Fixture::new();
    let unnamed = fixture.create(SocketType::Stream);
    assert_eq!(
        listen(&fixture.process, unnamed, 1).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
    let datagram = fixture.create(SocketType::Datagram);
    assert_eq!(
        listen(&fixture.process, datagram, 1).unwrap(),
        Err(UnixSocketError::Unsupported)
    );
    let (connected, _) = fixture.pair(SocketType::Stream);
    assert_eq!(
        listen(&fixture.process, connected, 1).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
    assert_eq!(
        fixture.receive(unnamed, 1).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
    assert_eq!(
        fixture.send(unnamed, b"x").unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(
        fixture
            .send_to(unnamed, &abstract_name(b"x"), b"x")
            .unwrap(),
        Err(UnixSocketError::Unsupported)
    );
    assert_eq!(
        fixture.readiness(unnamed),
        ReadinessFlags::WRITE | ReadinessFlags::CLOSED
    );
}

#[test]
fn full_backlogs_wait_for_accept() {
    let fixture = Fixture::new();
    let address = abstract_name(b"server");
    let listener = fixture.listener(&address, 0);
    let first = fixture.create(SocketType::Stream);
    let second = fixture.create(SocketType::Stream);
    assert_eq!(fixture.connect(first, &address).unwrap(), Ok(()));
    assert_eq!(
        fixture.connect(second, &address),
        Err(BrokerError::WouldBlock)
    );
    fixture.take_republished();

    let server = fixture.accept(listener).unwrap().unwrap();
    assert!(fixture.take_republished().contains(&second));
    assert_eq!(fixture.connect(second, &address).unwrap(), Ok(()));
    fixture.close(server);
    assert_eq!(
        fixture.send(first, b"x").unwrap(),
        Err(UnixSocketError::BrokenPipe)
    );
}

#[test]
fn closing_a_listener_resets_unaccepted_connections() {
    let fixture = Fixture::new();
    let address = abstract_name(b"server");
    let listener = fixture.listener(&address, 8);
    let client = fixture.create(SocketType::Stream);
    assert_eq!(fixture.connect(client, &address).unwrap(), Ok(()));
    assert_eq!(fixture.send(client, b"lost").unwrap(), Ok(4));
    let server = match &fixture
        .socket(client)
        .upgrade()
        .unwrap()
        .state
        .lock()
        .connection
    {
        Connection::Connected { peer, .. } => peer.clone(),
        Connection::None | Connection::Listening { .. } => panic!("the client is connected"),
    };
    fixture.close(listener);
    assert_eq!(fixture.queued(), (0, 0));
    assert!(server.upgrade().is_none());
    assert!(fixture.process.core.unix_sockets.names.read().is_empty());
    assert!(
        fixture
            .readiness(client)
            .contains(ReadinessFlags::READ | ReadinessFlags::HANGUP | ReadinessFlags::CLOSED)
    );
    assert_eq!(fixture.receive_data(client, 8), b"");
    assert_eq!(
        fixture.send(client, b"x").unwrap(),
        Err(UnixSocketError::BrokenPipe)
    );
}

#[test]
fn closed_listeners_refuse_connections_first() {
    let fixture = Fixture::new();
    let listener = fixture.listener(&abstract_name(b"listener"), 1);
    let closed = fixture.socket(listener).upgrade().unwrap();
    fixture.close(listener);
    let (client, _) = fixture.pair(SocketType::Stream);
    let client = fixture.socket(client).upgrade().unwrap();

    // A connect that found the listener before it closed is refused, even if
    // the client connected elsewhere meanwhile.
    assert_eq!(
        client.connect_stream(&closed, false).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
}

#[test]
fn sends_that_raced_a_reconnect_are_reset() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Datagram);
    let (stale, _) = fixture.pair(SocketType::Datagram);
    let stale = fixture.socket(stale).upgrade().unwrap();
    let socket = fixture.socket(first).upgrade().unwrap();

    // A send that found a closed peer the socket no longer connects to is
    // reset, and the current connection stays.
    assert_eq!(
        socket.disconnect_from(Arc::as_ptr(&stale)),
        Err(UnixSocketError::ConnectionReset)
    );
    assert_eq!(fixture.send(first, b"x").unwrap(), Ok(1));
    assert_eq!(fixture.receive_data(second, 8), b"x");
}

#[test]
fn shutdown_reaches_the_stream_peer() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Stream);
    assert_eq!(fixture.send(first, b"tail").unwrap(), Ok(4));
    shutdown(&fixture.process, first, ShutdownMode::Write)
        .unwrap()
        .unwrap();
    assert!(fixture.take_republished().contains(&second));
    assert_eq!(
        fixture.send(first, b"x").unwrap(),
        Err(UnixSocketError::BrokenPipe)
    );
    assert!(
        fixture
            .readiness(second)
            .contains(ReadinessFlags::READ | ReadinessFlags::HANGUP)
    );
    assert_eq!(fixture.receive_data(second, 8), b"tail");
    assert_eq!(fixture.receive_data(second, 8), b"");
    assert_eq!(fixture.send(second, b"ok").unwrap(), Ok(2));
    assert_eq!(fixture.receive_data(first, 8), b"ok");

    shutdown(&fixture.process, first, ShutdownMode::Read)
        .unwrap()
        .unwrap();
    assert!(fixture.readiness(first).contains(ReadinessFlags::CLOSED));
    assert_eq!(
        fixture.send(second, b"x").unwrap(),
        Err(UnixSocketError::BrokenPipe)
    );
    assert_eq!(
        shutdown(&fixture.process, first, ShutdownMode::Abort),
        Err(BrokerError::UnsupportedOperation)
    );
}

#[test]
fn closing_a_stream_hangs_up_its_peer() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Stream);
    assert_eq!(fixture.send(second, b"unread").unwrap(), Ok(6));
    fixture.close(first);
    assert!(fixture.take_republished().contains(&second));
    assert_eq!(fixture.queued(), (0, 0));
    assert_eq!(
        fixture.readiness(second),
        ReadinessFlags::READ
            | ReadinessFlags::WRITE
            | ReadinessFlags::HANGUP
            | ReadinessFlags::CLOSED
    );
    assert_eq!(fixture.receive_data(second, 8), b"");
    assert_eq!(
        fixture.send(second, b"x").unwrap(),
        Err(UnixSocketError::BrokenPipe)
    );
}

#[test]
fn full_streams_wait_for_the_reader() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Stream);
    let data = vec![7; CAPACITY + 1];
    assert_eq!(fixture.send(first, &data).unwrap(), Ok(CAPACITY));
    assert_eq!(fixture.send(first, b"x"), Err(BrokerError::WouldBlock));
    assert!(!fixture.readiness(first).contains(ReadinessFlags::WRITE));
    fixture.take_republished();

    assert_eq!(fixture.receive_data(second, 1).len(), 1);
    assert!(fixture.take_republished().contains(&first));
    assert!(fixture.readiness(first).contains(ReadinessFlags::WRITE));
    assert_eq!(fixture.send(first, &data).unwrap(), Ok(1));
    assert_eq!(fixture.queued(), (CAPACITY, CAPACITY));
    assert_eq!(
        fixture.send(first, &vec![0; MAX_UNIX_SOCKET_TRANSFER_SIZE as usize + 1]),
        Err(BrokerError::ResourceExhausted)
    );
}

#[test]
fn datagrams_keep_boundaries_and_sources() {
    let fixture = Fixture::new();
    let receiver_address = abstract_name(b"receiver");
    let receiver = fixture.create(SocketType::Datagram);
    fixture.bind(receiver, &receiver_address).unwrap();
    let named = fixture.create(SocketType::Datagram);
    fixture.bind(named, &path("/named")).unwrap();
    let unnamed = fixture.create(SocketType::Datagram);

    assert_eq!(
        fixture.send_to(named, &receiver_address, b"abc").unwrap(),
        Ok(3)
    );
    assert_eq!(
        fixture.send_to(unnamed, &receiver_address, b"").unwrap(),
        Ok(0)
    );
    assert_eq!(
        fixture
            .send_to(unnamed, &receiver_address, b"defgh")
            .unwrap(),
        Ok(5)
    );

    assert_eq!(
        fixture.receive(receiver, 2).unwrap().unwrap(),
        Received {
            data: b"ab".to_vec(),
            length: 3,
            source: Some(path("/named").name()),
        }
    );
    assert_eq!(
        fixture.receive(receiver, 8).unwrap().unwrap(),
        Received {
            source: Some(UnixSocketName::Unnamed),
            ..Received::default()
        }
    );
    let peeked = receive(&fixture.process, receiver, 8, true, false, false)
        .unwrap()
        .unwrap();
    assert_eq!(peeked.data, b"defgh");
    assert_eq!(peeked.source, None);
    assert_eq!(fixture.receive_data(receiver, 8), b"defgh");
    assert_eq!(fixture.receive(receiver, 8), Err(BrokerError::WouldBlock));
    assert_eq!(fixture.queued(), (0, 0));

    assert_eq!(
        fixture.send(unnamed, b"x").unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(
        fixture
            .send_to(unnamed, &receiver_address, &vec![0; CAPACITY + 1])
            .unwrap(),
        Err(UnixSocketError::MessageTooLarge)
    );
}

#[test]
fn connected_datagram_sockets_only_accept_their_peer() {
    let fixture = Fixture::new();
    let receiver_address = abstract_name(b"receiver");
    let receiver = fixture.create(SocketType::Datagram);
    fixture.bind(receiver, &receiver_address).unwrap();
    let peer_address = abstract_name(b"peer");
    let peer = fixture.create(SocketType::Datagram);
    fixture.bind(peer, &peer_address).unwrap();
    let other = fixture.create(SocketType::Datagram);

    assert_eq!(fixture.connect(receiver, &peer_address).unwrap(), Ok(()));
    assert_eq!(
        fixture.send_to(other, &receiver_address, b"x").unwrap(),
        Err(UnixSocketError::NotPermitted)
    );
    assert_eq!(
        fixture.connect(other, &receiver_address).unwrap(),
        Err(UnixSocketError::NotPermitted)
    );
    assert_eq!(
        fixture.send_to(peer, &receiver_address, b"x").unwrap(),
        Ok(1)
    );
    assert_eq!(fixture.send(receiver, b"y").unwrap(), Ok(1));
    assert_eq!(
        fixture.receive(peer, 1).unwrap().unwrap().source,
        Some(receiver_address.name())
    );
    assert_eq!(
        name(&fixture.process, receiver, true).unwrap(),
        Ok(peer_address.name())
    );

    // A closed peer is gone even while an operation still holds it, so the
    // send disconnects before checking its own shutdown.
    let held = fixture.socket(peer).upgrade().unwrap();
    fixture.close(peer);
    shutdown(&fixture.process, receiver, ShutdownMode::Write)
        .unwrap()
        .unwrap();
    assert_ne!(fixture.queued(), (0, 0));
    assert_eq!(
        fixture.send(receiver, b"z").unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
    assert_eq!(fixture.queued(), (0, 0));
    assert_eq!(
        fixture.send(receiver, b"z").unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    drop(held);
}

#[test]
fn reconnecting_a_datagram_socket_drops_queued_datagrams() {
    let fixture = Fixture::new();
    let receiver_address = abstract_name(b"receiver");
    let receiver = fixture.create(SocketType::Datagram);
    fixture.bind(receiver, &receiver_address).unwrap();
    let first_address = abstract_name(b"first");
    let first = fixture.create(SocketType::Datagram);
    fixture.bind(first, &first_address).unwrap();
    let second_address = abstract_name(b"second");
    let second = fixture.create(SocketType::Datagram);
    fixture.bind(second, &second_address).unwrap();

    assert_eq!(fixture.connect(receiver, &first_address).unwrap(), Ok(()));
    assert_eq!(
        fixture.send_to(first, &receiver_address, b"x").unwrap(),
        Ok(1)
    );
    assert_eq!(fixture.connect(receiver, &first_address).unwrap(), Ok(()));
    assert_eq!(
        fixture.queued(),
        (1 + DATAGRAM_OVERHEAD, 1 + DATAGRAM_OVERHEAD)
    );

    assert_eq!(fixture.connect(receiver, &second_address).unwrap(), Ok(()));
    assert_eq!(fixture.queued(), (0, 0));
    assert!(!fixture.readiness(receiver).contains(ReadinessFlags::READ));
    assert_eq!(
        receive(&fixture.process, receiver, 1, false, false, true),
        Err(BrokerError::NonBlockingWouldBlock)
    );
}

#[test]
fn full_datagram_receivers_wake_connected_senders() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Datagram);
    let datagram = vec![0; CAPACITY / 2];
    assert_eq!(fixture.send(first, &datagram).unwrap(), Ok(datagram.len()));
    assert_eq!(fixture.send(first, &datagram).unwrap(), Ok(datagram.len()));
    assert_eq!(fixture.send(first, b"x"), Err(BrokerError::WouldBlock));
    assert!(!fixture.readiness(first).contains(ReadinessFlags::WRITE));
    fixture.take_republished();

    assert_eq!(fixture.receive_data(second, 1).len(), 1);
    assert!(fixture.take_republished().contains(&first));
    assert!(fixture.readiness(first).contains(ReadinessFlags::WRITE));
    assert_eq!(fixture.send(first, b"x").unwrap(), Ok(1));
}

#[test]
fn connecting_a_full_datagram_receiver_wakes_rejected_senders() {
    let fixture = Fixture::new();
    let receiver_address = abstract_name(b"receiver");
    let receiver = fixture.create(SocketType::Datagram);
    fixture.bind(receiver, &receiver_address).unwrap();
    let peer_address = abstract_name(b"peer");
    let peer = fixture.create(SocketType::Datagram);
    fixture.bind(peer, &peer_address).unwrap();
    let sender = fixture.create(SocketType::Datagram);
    let datagram = vec![0; CAPACITY / 2];
    for _ in 0..2 {
        assert_eq!(
            fixture
                .send_to(sender, &receiver_address, &datagram)
                .unwrap(),
            Ok(datagram.len())
        );
    }
    assert_eq!(
        fixture.send_to(sender, &receiver_address, b"x"),
        Err(BrokerError::WouldBlock)
    );
    fixture.take_republished();

    assert_eq!(fixture.connect(receiver, &peer_address).unwrap(), Ok(()));
    assert!(fixture.take_republished().contains(&sender));
    assert_eq!(
        fixture.send_to(sender, &receiver_address, b"x").unwrap(),
        Err(UnixSocketError::NotPermitted)
    );
}

#[test]
fn queued_bytes_are_limited_and_refunded() {
    let fixture =
        Fixture::with_limits(BrokerCoreLimits::DEFAULT.with_unix_socket_limits(usize::MAX, 1000));
    let (first, second) = fixture.pair(SocketType::Stream);
    let mut sockets = vec![fixture.socket(first), fixture.socket(second)];
    assert_eq!(fixture.send(first, &[0; 600]).unwrap(), Ok(600));
    assert_eq!(
        fixture.send(first, &[0; 600]),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(fixture.queued(), (600, 600));
    assert_eq!(fixture.receive_data(second, 100).len(), 100);
    assert_eq!(fixture.queued(), (500, 500));
    fixture.close(second);
    assert_eq!(fixture.queued(), (0, 0));
    fixture.close(first);

    let (first, second) = fixture.pair(SocketType::Datagram);
    sockets.extend([fixture.socket(first), fixture.socket(second)]);
    assert_eq!(fixture.send(first, &[0; 600]).unwrap(), Ok(600));
    assert_eq!(
        fixture.queued(),
        (600 + DATAGRAM_OVERHEAD, 600 + DATAGRAM_OVERHEAD)
    );
    assert_eq!(
        fixture.send(first, &[0; 200]),
        Err(BrokerError::ResourceExhausted)
    );
    fixture.close(first);
    fixture.close(second);
    assert_eq!(fixture.queued(), (0, 0));
    assert!(sockets.iter().all(|socket| socket.upgrade().is_none()));
}

#[test]
fn unaccepted_connections_are_charged_to_the_listener() {
    let fixture = Fixture::with_limits(
        BrokerCoreLimits::DEFAULT.with_unix_socket_limits(usize::MAX, CONNECTION_OVERHEAD),
    );
    let address = abstract_name(b"server");
    let listener = fixture.listener(&address, 8);
    let first = fixture.create(SocketType::Stream);
    assert_eq!(fixture.connect(first, &address).unwrap(), Ok(()));
    assert_eq!(fixture.queued(), (CONNECTION_OVERHEAD, CONNECTION_OVERHEAD));
    let second = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect(second, &address),
        Err(BrokerError::ResourceExhausted)
    );

    let accepted = fixture.accept(listener).unwrap().unwrap();
    assert_eq!(fixture.queued(), (0, 0));
    assert_eq!(fixture.connect(second, &address).unwrap(), Ok(()));
    fixture.close(listener);
    assert_eq!(fixture.queued(), (0, 0));
    fixture.close(accepted);
}

#[test]
fn duplicated_references_share_one_socket() {
    let fixture = Fixture::new();
    let child = fixture
        .broker
        .create_process(
            CallerCredential::Unauthenticated,
            Some(fixture.process.id()),
        )
        .unwrap();
    let (first, second) = fixture.pair(SocketType::Stream);
    let duplicated = fixture
        .process
        .duplicate_object_reference_to(first, &child, ObjectRights::all())
        .unwrap();
    fixture.close(first);
    assert_eq!(fixture.send(second, b"child").unwrap(), Ok(5));
    assert_eq!(
        receive(&child, duplicated, 8, false, false, false)
            .unwrap()
            .unwrap()
            .data,
        b"child"
    );
    child.close_object_reference(duplicated).unwrap();
    assert_eq!(fixture.receive_data(second, 8), b"");
}

#[test]
fn sockets_connect_to_themselves_only_as_datagram_sockets() {
    let fixture = Fixture::new();
    let listening_address = abstract_name(b"listening");
    let listener = fixture.listener(&listening_address, 8);
    assert_eq!(
        fixture.connect(listener, &listening_address).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
    let bound_address = abstract_name(b"bound");
    let bound = fixture.create(SocketType::Stream);
    fixture.bind(bound, &bound_address).unwrap();
    assert_eq!(
        fixture.connect(bound, &bound_address).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );

    let address = abstract_name(b"datagram");
    let datagram = fixture.create(SocketType::Datagram);
    fixture.bind(datagram, &address).unwrap();
    assert_eq!(fixture.connect(datagram, &address).unwrap(), Ok(()));
    assert_eq!(fixture.send(datagram, b"self").unwrap(), Ok(4));
    let received = fixture.receive(datagram, 8).unwrap().unwrap();
    assert_eq!(received.data, b"self");
    assert_eq!(received.source, Some(address.name()));
}

#[test]
fn stream_directions_transfer_in_parallel() {
    const LENGTH: usize = 4 * CAPACITY;
    const CHUNK: u32 = 4096;
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Stream);
    let data: Vec<u8> = (0..LENGTH)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    std::thread::scope(|scope| {
        for (sender, receiver) in [(first, second), (second, first)] {
            let (fixture, data) = (&fixture, &data);
            scope.spawn(move || {
                let mut sent = 0;
                while sent < LENGTH {
                    let end = LENGTH.min(sent + CHUNK as usize);
                    sent += Fixture::retry(|| fixture.send(sender, &data[sent..end])).unwrap();
                }
            });
            scope.spawn(move || {
                let mut received = Vec::new();
                while received.len() < LENGTH {
                    let chunk = Fixture::retry(|| fixture.receive(receiver, CHUNK));
                    received.extend(chunk.unwrap().data);
                }
                assert_eq!(received, *data);
            });
        }
    });
    assert_eq!(fixture.queued(), (0, 0));
}

#[test]
fn datagram_senders_share_a_receiver_in_parallel() {
    const SENDERS: usize = 4;
    const DATAGRAMS: u16 = 500;
    let fixture = Fixture::new();
    let address = abstract_name(b"receiver");
    let receiver = fixture.create(SocketType::Datagram);
    fixture.bind(receiver, &address).unwrap();
    let senders: Vec<_> = (0..SENDERS)
        .map(|_| fixture.create(SocketType::Datagram))
        .collect();
    std::thread::scope(|scope| {
        for (index, &sender) in senders.iter().enumerate() {
            let (fixture, address) = (&fixture, &address);
            scope.spawn(move || {
                for sequence in 0..DATAGRAMS {
                    let [high, low] = sequence.to_be_bytes();
                    let datagram = [u8::try_from(index).unwrap(), high, low];
                    let sent = Fixture::retry(|| fixture.send_to(sender, address, &datagram));
                    assert_eq!(sent, Ok(3));
                }
            });
        }
        let mut next = [0; SENDERS];
        for _ in 0..SENDERS * usize::from(DATAGRAMS) {
            let datagram = Fixture::retry(|| fixture.receive(receiver, 8)).unwrap();
            let [index, high, low] = datagram.data[..] else {
                panic!("datagrams keep their boundaries");
            };
            let sequence = &mut next[usize::from(index)];
            assert_eq!(u16::from_be_bytes([high, low]), *sequence);
            *sequence += 1;
        }
    });
    assert_eq!(fixture.queued(), (0, 0));
}

#[test]
fn closing_a_peer_races_with_sending() {
    let fixture = Fixture::new();
    for (socket_type, refused) in [
        (SocketType::Stream, UnixSocketError::BrokenPipe),
        (SocketType::Datagram, UnixSocketError::ConnectionRefused),
    ] {
        for _ in 0..50 {
            let (first, second) = fixture.pair(socket_type);
            let sockets = [fixture.socket(first), fixture.socket(second)];
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    loop {
                        match fixture.send(first, &[0; 1024]) {
                            Ok(Ok(_)) | Err(BrokerError::WouldBlock) => {}
                            Ok(Err(error)) if error == refused => break,
                            other => panic!("unexpected send result {other:?}"),
                        }
                    }
                });
                scope.spawn(|| fixture.close(second));
            });
            fixture.close(first);
            assert_eq!(fixture.queued(), (0, 0));
            assert!(sockets.iter().all(|socket| socket.upgrade().is_none()));
        }
    }
}

#[test]
fn opposite_connects_do_not_deadlock() {
    let fixture = Fixture::new();
    for round in 0..100_u32 {
        let listening_address = abstract_name(&round.to_be_bytes());
        let bound_address = abstract_name(&(!round).to_be_bytes());
        let listener = fixture.listener(&listening_address, 8);
        let bound = fixture.create(SocketType::Stream);
        fixture.bind(bound, &bound_address).unwrap();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                assert_eq!(fixture.connect(bound, &listening_address).unwrap(), Ok(()));
            });
            scope.spawn(|| {
                assert_eq!(
                    fixture.connect(listener, &bound_address).unwrap(),
                    Err(UnixSocketError::InvalidArgument)
                );
            });
        });
        fixture.close(listener);
        fixture.close(bound);
    }
    assert_eq!(fixture.queued(), (0, 0));
}
