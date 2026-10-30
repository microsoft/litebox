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

/// A receive's result with its bytes.
#[derive(Debug, Default, PartialEq, Eq)]
struct Message {
    data: Vec<u8>,
    length: usize,
    source: Option<UnixSocketName>,
}

/// Receives up to `capacity` bytes from a Unix socket into a new vector.
fn receive_message(
    process: &BrokerProcess,
    handle: ObjectHandle,
    capacity: u32,
    peek: bool,
    source: bool,
    nonblocking: bool,
) -> Result<UnixSocketResult<Message>> {
    let mut data = vec![0; capacity as usize];
    let result = receive(process, handle, &mut data, peek, source, nonblocking)?;
    Ok(result.map(|received| {
        data.truncate(received.received);
        Message {
            data,
            length: received.length,
            source: received.source,
        }
    }))
}

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
        Self::build_with_random(limits, rights, Arc::new(crate::random::TestRandomProvider))
    }

    fn without_randomness() -> Self {
        Self::build_with_random(
            BrokerCoreLimits::DEFAULT,
            ObjectRights::all(),
            Arc::new(crate::test_support::FailingRandomProvider),
        )
    }

    fn build_with_random(
        limits: BrokerCoreLimits,
        rights: ObjectRights,
        random_provider: Arc<dyn crate::random::RandomProvider>,
    ) -> Self {
        let fs = Resolver::<TestPlatform, _>::new(InMem::<TestPlatform>::new(
            InodeAllocator::standalone(),
        ));
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(rights))
            .with_limits(limits)
            .with_file_service(Arc::new(fs))
            .with_random_provider(random_provider)
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
        self.typed_listener(SocketType::Stream, address, backlog)
    }

    fn typed_listener(
        &self,
        socket_type: SocketType,
        address: &UnixSocketAddress,
        backlog: u32,
    ) -> ObjectHandle {
        let listener = self.create(socket_type);
        self.bind(listener, address).unwrap();
        listen(&self.process, listener, backlog).unwrap().unwrap();
        listener
    }

    /// Connects `handle` to `address`, which is not the host's.
    fn connect(
        &self,
        handle: ObjectHandle,
        address: &UnixSocketAddress,
    ) -> Result<UnixSocketResult<()>> {
        let result = connect(&self.process, handle, address, USER)?;
        Ok(result.map(|status| assert_eq!(status, SocketConnectionStatus::Connected)))
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
        send(&self.process, handle, None, &data, USER)
    }

    fn send_to(
        &self,
        handle: ObjectHandle,
        address: &UnixSocketAddress,
        data: &[u8],
    ) -> Result<UnixSocketResult<usize>> {
        send(&self.process, handle, Some(address), &data, USER)
    }

    fn receive(&self, handle: ObjectHandle, capacity: u32) -> Result<UnixSocketResult<Message>> {
        receive_message(&self.process, handle, capacity, false, true, false)
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

fn vsock(port: u32) -> UnixSocketAddress {
    UnixSocketAddress::Vsock {
        cid: VMADDR_CID_ANY,
        port,
    }
}

fn guest_vsock_name(port: u32) -> UnixSocketName {
    UnixSocketName::Vsock {
        cid: VMADDR_CID_ANY,
        port,
    }
}

impl Fixture {
    fn connect_from_host(
        &self,
        handle: ObjectHandle,
        guest_port: u32,
        host_port: u32,
    ) -> Result<UnixSocketResult<()>> {
        connect_from_vsock_host(&self.process, handle, guest_port, host_port)
    }
}

#[test]
fn stream_pairs_carry_bytes_in_both_directions() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Stream);
    assert!(!fixture.readiness(second).contains(ReadinessFlags::READ));
    assert_eq!(fixture.send(first, b"hello").unwrap(), Ok(5));
    assert!(fixture.take_republished().contains(&second));
    assert!(fixture.readiness(second).contains(ReadinessFlags::READ));

    let peeked = receive_message(&fixture.process, second, 3, true, true, false)
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
        Ok(SocketConnectionStatus::Connected)
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
        Connection::None | Connection::Connecting { .. } | Connection::Listening { .. } => {
            panic!("the client is connected")
        }
    };
    fixture.close(listener);
    assert_eq!(fixture.queued(), (0, 0));
    assert!(server.upgrade().is_none());
    assert!(
        fixture
            .process
            .core
            .unix_sockets
            .registry
            .read()
            .names
            .is_empty()
    );
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
        client.connect_to_listener(&closed, false).unwrap(),
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
fn shutdown_reaches_the_connected_peer() {
    let fixture = Fixture::new();
    for socket_type in [SocketType::Stream, SocketType::SeqPacket] {
        let (first, second) = fixture.pair(socket_type);
        assert_eq!(fixture.send(first, b"tail").unwrap(), Ok(4));
        fixture.take_republished();
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
        assert_eq!(
            receive_message(&fixture.process, second, 8, false, false, true),
            Ok(Ok(Message::default()))
        );
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
}

#[test]
fn closing_a_connected_socket_hangs_up_its_peer() {
    let fixture = Fixture::new();
    for socket_type in [SocketType::Stream, SocketType::SeqPacket] {
        let (first, second) = fixture.pair(socket_type);
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
        Message {
            data: b"ab".to_vec(),
            length: 3,
            source: Some(path("/named").name()),
        }
    );
    assert_eq!(
        fixture.receive(receiver, 8).unwrap().unwrap(),
        Message {
            source: Some(UnixSocketName::Unnamed),
            ..Message::default()
        }
    );
    let peeked = receive_message(&fixture.process, receiver, 8, true, false, false)
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
        receive_message(&fixture.process, receiver, 1, false, false, true),
        Err(BrokerError::NonBlockingWouldBlock)
    );
}

#[test]
fn full_record_receivers_wake_connected_senders() {
    let fixture = Fixture::new();
    for socket_type in [SocketType::Datagram, SocketType::SeqPacket] {
        let (first, second) = fixture.pair(socket_type);
        let record = vec![0; CAPACITY / 2];
        assert_eq!(fixture.send(first, &record).unwrap(), Ok(record.len()));
        assert_eq!(fixture.send(first, &record).unwrap(), Ok(record.len()));
        assert_eq!(fixture.send(first, b"x"), Err(BrokerError::WouldBlock));
        assert!(!fixture.readiness(first).contains(ReadinessFlags::WRITE));
        fixture.take_republished();

        assert_eq!(fixture.receive_data(second, 1).len(), 1);
        assert!(fixture.take_republished().contains(&first));
        assert!(fixture.readiness(first).contains(ReadinessFlags::WRITE));
        assert_eq!(fixture.send(first, b"x").unwrap(), Ok(1));
    }
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
fn sequenced_packets_keep_boundaries_over_connections() {
    let fixture = Fixture::new();
    let address = abstract_name(b"server");
    let listener = fixture.typed_listener(SocketType::SeqPacket, &address, 8);
    let client = fixture.create(SocketType::SeqPacket);
    assert_eq!(fixture.connect(client, &address).unwrap(), Ok(()));
    let server = fixture.accept(listener).unwrap().unwrap();
    assert_eq!(
        fixture.socket(server).upgrade().unwrap().kind,
        SocketType::SeqPacket
    );

    assert_eq!(fixture.send(client, b"abc").unwrap(), Ok(3));
    assert_eq!(fixture.send(client, b"").unwrap(), Ok(0));
    // Like Linux, a connected sequenced-packet socket ignores the address.
    assert_eq!(
        fixture
            .send_to(client, &abstract_name(b"elsewhere"), b"defgh")
            .unwrap(),
        Ok(5)
    );
    assert_eq!(
        fixture.receive(server, 2).unwrap().unwrap(),
        Message {
            data: b"ab".to_vec(),
            length: 3,
            source: Some(UnixSocketName::Unnamed),
        }
    );
    assert_eq!(
        fixture.receive(server, 8).unwrap().unwrap(),
        Message {
            source: Some(UnixSocketName::Unnamed),
            ..Message::default()
        }
    );
    let peeked = receive_message(&fixture.process, server, 8, true, false, false)
        .unwrap()
        .unwrap();
    assert_eq!(peeked.data, b"defgh");
    assert_eq!(fixture.receive_data(server, 8), b"defgh");
    assert_eq!(fixture.receive(server, 8), Err(BrokerError::WouldBlock));

    assert_eq!(fixture.send(server, b"pong").unwrap(), Ok(4));
    let received = fixture.receive(client, 8).unwrap().unwrap();
    assert_eq!(received.data, b"pong");
    assert_eq!(received.source, Some(address.name()));
    assert_eq!(
        fixture.send(client, &vec![0; CAPACITY + 1]).unwrap(),
        Err(UnixSocketError::MessageTooLarge)
    );
    assert_eq!(fixture.queued(), (0, 0));
}

#[test]
fn unconnected_sequenced_packet_sockets_reject_data_operations() {
    let fixture = Fixture::new();
    let address = abstract_name(b"server");
    let unconnected = fixture.create(SocketType::SeqPacket);
    let listener = fixture.typed_listener(SocketType::SeqPacket, &address, 1);
    for handle in [unconnected, listener] {
        assert_eq!(
            fixture.send(handle, b"x").unwrap(),
            Err(UnixSocketError::NotConnected)
        );
        assert_eq!(
            fixture.send_to(handle, &address, b"x").unwrap(),
            Err(UnixSocketError::NotConnected)
        );
        assert_eq!(
            fixture.receive(handle, 1).unwrap(),
            Err(UnixSocketError::NotConnected)
        );
    }
    assert_eq!(
        fixture.readiness(unconnected),
        ReadinessFlags::WRITE | ReadinessFlags::CLOSED
    );
}

#[test]
fn sequenced_packet_sockets_connect_only_to_their_type() {
    let fixture = Fixture::new();
    let address = abstract_name(b"server");
    fixture.listener(&address, 1);
    fixture.listener(&path("/server"), 1);
    let client = fixture.create(SocketType::SeqPacket);
    assert_eq!(
        fixture.connect(client, &address).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
    assert_eq!(
        fixture.connect(client, &path("/server")).unwrap(),
        Err(UnixSocketError::WrongType)
    );

    let listener = fixture.typed_listener(SocketType::SeqPacket, &address, 1);
    assert_eq!(fixture.connect(client, &address).unwrap(), Ok(()));
    assert!(fixture.accept(listener).unwrap().is_ok());
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
        receive_message(&child, duplicated, 8, false, false, false)
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

#[test]
fn vsock_ports_are_apart_from_unix_names() {
    let fixture = Fixture::new();
    let unix = fixture.listener(&abstract_name(b"vsock:1024"), 1);
    let native = fixture.listener(&vsock(1024), 1);
    assert_eq!(
        name(&fixture.process, native, false).unwrap(),
        Ok(guest_vsock_name(1024))
    );

    // A Unix connection reaches only the Unix listener, and the host's only
    // the vsock one.
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture
            .connect(client, &abstract_name(b"vsock:1024"))
            .unwrap(),
        Ok(())
    );
    let host = fixture.create(SocketType::Stream);
    assert_eq!(fixture.connect_from_host(host, 1024, 5).unwrap(), Ok(()));
    assert!(fixture.accept(unix).unwrap().is_ok());
    assert!(fixture.accept(native).unwrap().is_ok());
    assert_eq!(fixture.accept(unix), Err(BrokerError::WouldBlock));
    assert_eq!(fixture.accept(native), Err(BrokerError::WouldBlock));

    // Nor does the host reach a Unix listener.
    fixture.close(native);
    let host = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect_from_host(host, 1024, 5).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
}

#[test]
fn only_stream_sockets_bind_vsock_ports_at_any_cid() {
    let fixture = Fixture::new();
    for socket_type in [SocketType::Datagram, SocketType::SeqPacket] {
        let socket = fixture.create(socket_type);
        assert_eq!(
            fixture.bind(socket, &vsock(1024)),
            Err(UnixSocketError::InvalidArgument)
        );
    }
    let socket = fixture.create(SocketType::Stream);
    for cid in [0, 1, VMADDR_CID_HOST, 3] {
        assert_eq!(
            fixture.bind(socket, &UnixSocketAddress::Vsock { cid, port: 1024 }),
            Err(UnixSocketError::AddressNotAvailable)
        );
    }
    assert_eq!(fixture.bind(socket, &vsock(1024)), Ok(()));
    assert_eq!(
        fixture.bind(socket, &vsock(1025)),
        Err(UnixSocketError::InvalidArgument)
    );
    let other = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.bind(other, &vsock(1024)),
        Err(UnixSocketError::AddressInUse)
    );
    fixture.close(socket);
    assert_eq!(fixture.bind(other, &vsock(1024)), Ok(()));
}

#[test]
fn vsock_port_any_binds_an_unused_ephemeral_port() {
    let fixture = Fixture::new();
    let bound_port = |handle| match name(&fixture.process, handle, false).unwrap() {
        Ok(UnixSocketName::Vsock {
            cid: VMADDR_CID_ANY,
            port,
        }) => port,
        other => panic!("not a guest vsock name: {other:?}"),
    };
    let first = fixture.create(SocketType::Stream);
    assert_eq!(fixture.bind(first, &vsock(VMADDR_PORT_ANY)), Ok(()));
    let first_port = bound_port(first);
    assert!((FIRST_EPHEMERAL_VSOCK_PORT..VMADDR_PORT_ANY).contains(&first_port));

    // The next is taken, so the one after it is bound.
    let taken = fixture.create(SocketType::Stream);
    let next = if first_port == VMADDR_PORT_ANY - 1 {
        FIRST_EPHEMERAL_VSOCK_PORT
    } else {
        first_port + 1
    };
    fixture.bind(taken, &vsock(next)).unwrap();
    let second = fixture.create(SocketType::Stream);
    assert_eq!(fixture.bind(second, &vsock(VMADDR_PORT_ANY)), Ok(()));
    assert_ne!(bound_port(second), first_port);
    assert_ne!(bound_port(second), next);
    assert!(bound_port(second) >= FIRST_EPHEMERAL_VSOCK_PORT);
    let listener = fixture.create(SocketType::Stream);
    fixture.bind(listener, &vsock(VMADDR_PORT_ANY)).unwrap();
    listen(&fixture.process, listener, 1).unwrap().unwrap();
    let host = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture
            .connect_from_host(host, bound_port(listener), 5)
            .unwrap(),
        Ok(())
    );
}

#[test]
fn ephemeral_vsock_ports_wrap_and_give_up_when_taken() {
    let fixture = Fixture::new();
    let sockets = &fixture.process.core.unix_sockets;
    sockets.registry.write().next_ephemeral_vsock_port = Some(EPHEMERAL_VSOCK_PORTS - 1);
    let last = fixture.create(SocketType::Stream);
    fixture.bind(last, &vsock(VMADDR_PORT_ANY)).unwrap();
    assert_eq!(
        name(&fixture.process, last, false).unwrap(),
        Ok(guest_vsock_name(VMADDR_PORT_ANY - 1))
    );

    // Every port the next bind tries is taken.
    for offset in 0..MAX_EPHEMERAL_VSOCK_PORT_ATTEMPTS {
        let socket = fixture.create(SocketType::Stream);
        fixture
            .bind(socket, &vsock(FIRST_EPHEMERAL_VSOCK_PORT + offset))
            .unwrap();
    }
    let socket = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.bind(socket, &vsock(VMADDR_PORT_ANY)),
        Err(UnixSocketError::AddressNotAvailable)
    );
    assert_eq!(
        name(&fixture.process, socket, false).unwrap(),
        Ok(UnixSocketName::Unnamed)
    );
    assert_eq!(fixture.bind(socket, &vsock(VMADDR_PORT_ANY)), Ok(()));
}

#[test]
fn only_ephemeral_binds_seed_vsock_ports_and_need_no_randomness() {
    let fixture = Fixture::without_randomness();
    let unseeded = || {
        fixture
            .process
            .core
            .unix_sockets
            .registry
            .read()
            .next_ephemeral_vsock_port
            .is_none()
    };
    let datagram = fixture.create(SocketType::Datagram);
    assert_eq!(
        fixture.bind(datagram, &vsock(VMADDR_PORT_ANY)),
        Err(UnixSocketError::InvalidArgument)
    );
    let socket = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.bind(
            socket,
            &UnixSocketAddress::Vsock {
                cid: 3,
                port: VMADDR_PORT_ANY
            }
        ),
        Err(UnixSocketError::AddressNotAvailable)
    );
    fixture.bind(socket, &vsock(2048)).unwrap();
    assert_eq!(
        fixture.bind(socket, &vsock(VMADDR_PORT_ANY)),
        Err(UnixSocketError::InvalidArgument)
    );
    assert!(unseeded());

    // Without randomness, the ports start at the first.
    let ephemeral = fixture.create(SocketType::Stream);
    assert_eq!(fixture.bind(ephemeral, &vsock(VMADDR_PORT_ANY)), Ok(()));
    assert_eq!(
        name(&fixture.process, ephemeral, false).unwrap(),
        Ok(guest_vsock_name(FIRST_EPHEMERAL_VSOCK_PORT))
    );
    assert!(!unseeded());
}

#[test]
fn vsock_addresses_are_unreachable_without_a_host_connector() {
    let fixture = Fixture::new();
    fixture.listener(&vsock(1024), 1);
    for address in [
        vsock(1024),
        UnixSocketAddress::Vsock {
            cid: VMADDR_CID_HOST,
            port: 1024,
        },
    ] {
        for socket_type in [SocketType::Stream, SocketType::Datagram] {
            let client = fixture.create(socket_type);
            assert_eq!(
                fixture.connect(client, &address).unwrap(),
                Err(UnixSocketError::Unreachable)
            );
        }
        let sender = fixture.create(SocketType::Datagram);
        assert_eq!(
            fixture.send_to(sender, &address, b"x").unwrap(),
            Err(UnixSocketError::Unreachable)
        );
    }
}

#[test]
fn host_connections_bear_the_hosts_name() {
    let fixture = Fixture::new();
    let listener = fixture.listener(&vsock(1024), 8);
    let host = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect_from_host(host, 1024, 49152).unwrap(),
        Ok(())
    );
    let host_name = UnixSocketName::Vsock {
        cid: VMADDR_CID_HOST,
        port: 49152,
    };
    assert_eq!(
        name(&fixture.process, host, false).unwrap(),
        Ok(host_name.clone())
    );
    assert_eq!(
        name(&fixture.process, host, true).unwrap(),
        Ok(guest_vsock_name(1024))
    );
    assert_eq!(
        fixture.connect_from_host(host, 1024, 49152).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );

    let server = fixture.accept(listener).unwrap().unwrap();
    assert_eq!(
        name(&fixture.process, server, false).unwrap(),
        Ok(guest_vsock_name(1024))
    );
    assert_eq!(
        name(&fixture.process, server, true).unwrap(),
        Ok(host_name.clone())
    );
    assert_eq!(fixture.send(host, b"ping").unwrap(), Ok(4));
    let received = fixture.receive(server, 8).unwrap().unwrap();
    assert_eq!(received.data, b"ping");
    assert_eq!(received.source, Some(host_name));
    assert_eq!(fixture.send(server, b"pong").unwrap(), Ok(4));
    assert_eq!(fixture.receive_data(host, 8), b"pong");

    // Host ports hold no name: a guest neither binds them nor finds them.
    let other = fixture.create(SocketType::Stream);
    assert_eq!(fixture.bind(other, &vsock(49152)), Ok(()));
}

#[test]
fn host_connections_are_refused_or_wait_like_others() {
    let fixture = Fixture::new();
    let host = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect_from_host(host, 1024, 5).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );

    // A full backlog does not wait.
    let listener = fixture.listener(&vsock(1024), 0);
    let first = fixture.create(SocketType::Stream);
    assert_eq!(fixture.connect_from_host(first, 1024, 6).unwrap(), Ok(()));
    let second = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect_from_host(second, 1024, 7),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    fixture.accept(listener).unwrap().unwrap();
    let third = fixture.create(SocketType::Stream);
    assert_eq!(fixture.connect_from_host(third, 1024, 7).unwrap(), Ok(()));

    // Only unnamed, unconnected streams connect.
    let named = fixture.create(SocketType::Stream);
    fixture.bind(named, &abstract_name(b"named")).unwrap();
    let (connected, _) = fixture.pair(SocketType::Stream);
    for socket in [named, connected] {
        assert_eq!(
            fixture.connect_from_host(socket, 1024, 8).unwrap(),
            Err(UnixSocketError::InvalidArgument)
        );
    }
    let datagram = fixture.create(SocketType::Datagram);
    assert_eq!(
        fixture.connect_from_host(datagram, 1024, 8).unwrap(),
        Err(UnixSocketError::WrongType)
    );
}

impl Fixture {
    /// Returns a host connection from host port 5 to a new listener on vsock
    /// port `port`, and the guest's accepted socket.
    fn host_connection(&self, port: u32) -> (ObjectHandle, ObjectHandle) {
        let listener = self.listener(&vsock(port), 1);
        let host = self.create(SocketType::Stream);
        self.connect_from_host(host, port, 5).unwrap().unwrap();
        let guest = self.accept(listener).unwrap().unwrap();
        self.close(listener);
        (host, guest)
    }
}

#[test]
fn vsock_sockets_shut_down_receiving_drop_queued_data() {
    let fixture = Fixture::new();
    for mode in [ShutdownMode::Read, ShutdownMode::Both] {
        let (host, guest) = fixture.host_connection(1024);
        assert_eq!(fixture.send(host, b"queued").unwrap(), Ok(6));
        assert_eq!(
            receive_message(&fixture.process, guest, 8, true, false, false)
                .unwrap()
                .unwrap()
                .data,
            b"queued"
        );
        shutdown(&fixture.process, guest, mode).unwrap().unwrap();
        assert!(fixture.readiness(guest).contains(ReadinessFlags::READ));
        for peek in [true, false] {
            assert_eq!(
                receive_message(&fixture.process, guest, 8, peek, false, true),
                Ok(Ok(Message::default()))
            );
        }
        assert_eq!(
            name(&fixture.process, guest, true).unwrap(),
            Err(UnixSocketError::NotConnected)
        );
        if mode == ShutdownMode::Read {
            assert_eq!(fixture.send(guest, b"reply").unwrap(), Ok(5));
            assert_eq!(fixture.receive_data(host, 8), b"reply");
        } else {
            assert_eq!(
                fixture.send(guest, b"reply").unwrap(),
                Err(UnixSocketError::BrokenPipe)
            );
        }
    }
}

#[test]
fn vsock_sockets_drain_data_their_peer_sent_before_shutting_down() {
    let fixture = Fixture::new();
    let (host, guest) = fixture.host_connection(1024);
    assert_eq!(fixture.send(host, b"tail").unwrap(), Ok(4));
    shutdown(&fixture.process, host, ShutdownMode::Write)
        .unwrap()
        .unwrap();
    assert_eq!(fixture.receive_data(guest, 8), b"tail");
    assert_eq!(fixture.receive_data(guest, 8), b"");
    // Only the socket that shut down loses its peer's name.
    assert_eq!(
        name(&fixture.process, guest, true).unwrap(),
        Ok(UnixSocketName::Vsock {
            cid: VMADDR_CID_HOST,
            port: 5
        })
    );
    assert_eq!(
        name(&fixture.process, host, true).unwrap(),
        Err(UnixSocketError::NotConnected)
    );
}

#[test]
fn vsock_sockets_shut_down_sending_keep_receiving() {
    let fixture = Fixture::new();
    let (host, guest) = fixture.host_connection(1024);
    assert_eq!(fixture.send(host, b"data").unwrap(), Ok(4));
    shutdown(&fixture.process, guest, ShutdownMode::Write)
        .unwrap()
        .unwrap();
    assert_eq!(
        name(&fixture.process, guest, true).unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(fixture.receive_data(guest, 8), b"data");
    // A later shutdown of receiving still drops what is queued.
    assert_eq!(fixture.send(host, b"late").unwrap(), Ok(4));
    shutdown(&fixture.process, guest, ShutdownMode::Read)
        .unwrap()
        .unwrap();
    assert_eq!(fixture.receive_data(guest, 8), b"");
}

#[test]
fn unix_sockets_shut_down_receiving_drain_queued_data() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Stream);
    assert_eq!(fixture.send(second, b"queued").unwrap(), Ok(6));
    shutdown(&fixture.process, first, ShutdownMode::Both)
        .unwrap()
        .unwrap();
    assert_eq!(fixture.receive_data(first, 8), b"queued");
    assert_eq!(
        name(&fixture.process, first, true).unwrap(),
        Ok(UnixSocketName::Unnamed)
    );
}

#[test]
fn unconnected_vsock_sockets_do_not_shut_down() {
    let fixture = Fixture::new();
    // Nor does one created as a vsock socket, before it has a name.
    let created = create_vsock(
        &fixture.process,
        FileOpenFlags::NONE,
        &fixture.readiness_sink,
    )
    .unwrap();
    let bound = fixture.create(SocketType::Stream);
    fixture.bind(bound, &vsock(1025)).unwrap();
    let listener = fixture.listener(&vsock(1024), 1);
    for socket in [created, bound, listener] {
        for mode in [ShutdownMode::Read, ShutdownMode::Write, ShutdownMode::Both] {
            assert_eq!(
                shutdown(&fixture.process, socket, mode).unwrap(),
                Err(UnixSocketError::NotConnected)
            );
        }
    }
    assert_eq!(fixture.readiness(created), ReadinessFlags::WRITE);
    assert_eq!(fixture.readiness(listener), ReadinessFlags::default());
    fixture.bind(created, &vsock(1026)).unwrap();
    for socket in [created, bound] {
        listen(&fixture.process, socket, 1).unwrap().unwrap();
    }
    for (socket, port) in [(listener, 1024), (bound, 1025), (created, 1026)] {
        let host = fixture.create(SocketType::Stream);
        assert_eq!(fixture.connect_from_host(host, port, 5).unwrap(), Ok(()));
        let guest = fixture.accept(socket).unwrap().unwrap();
        assert_eq!(fixture.send(host, b"ping").unwrap(), Ok(4));
        assert_eq!(fixture.receive_data(guest, 8), b"ping");
    }
}

#[test]
fn unconnected_unix_sockets_still_shut_down() {
    let fixture = Fixture::new();
    let unbound = fixture.create(SocketType::Stream);
    let bound = fixture.create(SocketType::Stream);
    fixture.bind(bound, &abstract_name(b"bound")).unwrap();
    let address = abstract_name(b"listener");
    let listener = fixture.listener(&address, 1);
    for socket in [unbound, bound, listener] {
        assert_eq!(
            shutdown(&fixture.process, socket, ShutdownMode::Both).unwrap(),
            Ok(())
        );
    }
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect(client, &address).unwrap(),
        Err(UnixSocketError::ConnectionRefused)
    );
}

#[test]
fn vsock_connects_and_addressed_sends_fail_by_the_sockets_state() {
    let fixture = Fixture::new();
    let address = UnixSocketAddress::Vsock {
        cid: VMADDR_CID_HOST,
        port: 1024,
    };
    let unbound = fixture.create(SocketType::Stream);
    let bound = fixture.create(SocketType::Stream);
    fixture.bind(bound, &vsock(1025)).unwrap();
    for socket in [unbound, bound] {
        assert_eq!(
            fixture.connect(socket, &address).unwrap(),
            Err(UnixSocketError::Unreachable)
        );
        assert_eq!(
            fixture.send_to(socket, &address, b"x").unwrap(),
            Err(UnixSocketError::Unsupported)
        );
    }
    let listener = fixture.listener(&vsock(1026), 1);
    assert_eq!(
        fixture.connect(listener, &address).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
    assert_eq!(
        fixture.send_to(listener, &address, b"x").unwrap(),
        Err(UnixSocketError::Unsupported)
    );

    // A peer's shutdown does not count; the socket's own does.
    let (host, guest) = fixture.host_connection(1024);
    shutdown(&fixture.process, host, ShutdownMode::Write)
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture.connect(guest, &address).unwrap(),
        Err(UnixSocketError::AlreadyConnected)
    );
    assert_eq!(
        fixture.connect(host, &address).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
    for socket in [guest, host] {
        assert_eq!(
            fixture.send_to(socket, &address, b"x").unwrap(),
            Err(UnixSocketError::AlreadyConnected)
        );
    }
}

fn host_port(port: u32) -> UnixSocketAddress {
    UnixSocketAddress::Vsock {
        cid: VMADDR_CID_HOST,
        port,
    }
}

fn host_name(port: u32) -> UnixSocketName {
    UnixSocketName::Vsock {
        cid: VMADDR_CID_HOST,
        port,
    }
}

impl Fixture {
    /// The broker's host connector, with up to `backlog` connects waiting
    /// beyond the first.
    fn host_connector(&self, backlog: u32) -> ObjectHandle {
        let connector = self.create(SocketType::Stream);
        listen_for_vsock_host(&self.process, connector, backlog)
            .unwrap()
            .unwrap();
        connector
    }

    fn connect_vsock(
        &self,
        handle: ObjectHandle,
        address: &UnixSocketAddress,
    ) -> UnixSocketResult<SocketConnectionStatus> {
        connect(&self.process, handle, address, USER).unwrap()
    }

    /// Starts `client`'s connect to the host's port `port`, and returns the
    /// connector's socket for it.
    fn connect_to_host(
        &self,
        connector: ObjectHandle,
        client: ObjectHandle,
        port: u32,
    ) -> ObjectHandle {
        assert_eq!(
            self.connect_vsock(client, &host_port(port)),
            Ok(SocketConnectionStatus::Connecting)
        );
        self.accept(connector).unwrap().unwrap()
    }

    fn complete(&self, host: ObjectHandle, result: UnixSocketResult<()>) -> UnixSocketResult<()> {
        complete_vsock_host_connect(&self.process, host, result).unwrap()
    }

    fn take_error(&self, handle: ObjectHandle) -> Option<UnixSocketError> {
        take_error(&self.process, handle).unwrap()
    }

    fn name(&self, handle: ObjectHandle, peer: bool) -> UnixSocketResult<UnixSocketName> {
        name(&self.process, handle, peer).unwrap()
    }
}

#[test]
fn vsock_connects_reach_only_the_host_through_its_connector() {
    let fixture = Fixture::new();
    let client = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect_vsock(client, &host_port(1024)),
        Err(UnixSocketError::Unreachable)
    );
    // Not bound by the attempt.
    assert_eq!(fixture.name(client, false), Ok(UnixSocketName::Unnamed));

    let connector = fixture.host_connector(8);
    for cid in [VMADDR_CID_ANY, 1, 3] {
        let address = UnixSocketAddress::Vsock { cid, port: 1024 };
        assert_eq!(
            fixture.connect_vsock(client, &address),
            Err(UnixSocketError::Unreachable)
        );
    }
    assert_eq!(fixture.name(client, false), Ok(UnixSocketName::Unnamed));
    // Nor do sockets of other types, or with Unix names.
    for socket_type in [SocketType::Datagram, SocketType::SeqPacket] {
        let socket = fixture.create(socket_type);
        assert_eq!(
            fixture.connect_vsock(socket, &host_port(1024)),
            Err(UnixSocketError::Unreachable)
        );
    }
    let named = fixture.create(SocketType::Stream);
    fixture.bind(named, &abstract_name(b"unix")).unwrap();
    assert_eq!(
        fixture.connect_vsock(named, &host_port(1024)),
        Err(UnixSocketError::Unreachable)
    );
    assert_eq!(fixture.accept(connector), Err(BrokerError::WouldBlock));

    // One connector per broker, which no guest binds or connects to.
    let other = fixture.create(SocketType::Stream);
    assert_eq!(
        listen_for_vsock_host(&fixture.process, other, 8).unwrap(),
        Err(UnixSocketError::AddressInUse)
    );
    assert_eq!(
        fixture.bind(connector, &vsock(1024)),
        Err(UnixSocketError::InvalidArgument)
    );
    assert_eq!(
        fixture.connect_vsock(connector, &host_port(1024)),
        Err(UnixSocketError::InvalidArgument)
    );
    let bound = fixture.listener(&vsock(1024), 1);
    assert_eq!(
        listen_for_vsock_host(&fixture.process, bound, 8).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
}

#[test]
fn vsock_connects_wait_for_the_host_from_an_ephemeral_or_bound_port() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    let client = fixture.create(SocketType::Stream);
    let host = fixture.connect_to_host(connector, client, 5000);
    let Ok(UnixSocketName::Vsock {
        cid: VMADDR_CID_ANY,
        port,
    }) = fixture.name(client, false)
    else {
        panic!("not bound to a guest port");
    };
    assert!(port >= FIRST_EPHEMERAL_VSOCK_PORT);
    // The connector's socket names both ends.
    assert_eq!(fixture.name(host, false), Ok(host_name(5000)));
    assert_eq!(fixture.name(host, true), Ok(guest_vsock_name(port)));

    // Connecting: no peer, no data, no readiness, nor another connect.
    assert_eq!(fixture.readiness(client), ReadinessFlags::default());
    assert_eq!(
        fixture.name(client, true),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(
        fixture.send(client, b"early").unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(
        fixture.receive(client, 8).unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(
        shutdown(&fixture.process, client, ShutdownMode::Write).unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(
        listen(&fixture.process, client, 1).unwrap(),
        Err(UnixSocketError::InvalidArgument)
    );
    for address in [host_port(5000), host_port(5001), vsock(1)] {
        assert_eq!(
            fixture.connect_vsock(client, &address),
            Err(UnixSocketError::AlreadyInProgress)
        );
    }
    assert_eq!(fixture.take_error(client), None);

    fixture.take_republished();
    assert_eq!(fixture.complete(host, Ok(())), Ok(()));
    assert!(fixture.take_republished().contains(&client));
    assert!(fixture.readiness(client).contains(ReadinessFlags::WRITE));
    assert_eq!(fixture.name(client, true), Ok(host_name(5000)));
    assert_eq!(fixture.send(client, b"ping").unwrap(), Ok(4));
    assert_eq!(fixture.receive_data(host, 8), b"ping");
    assert_eq!(fixture.send(host, b"pong").unwrap(), Ok(4));
    assert_eq!(fixture.receive_data(client, 8), b"pong");
    assert_eq!(
        fixture.connect_vsock(client, &host_port(5000)),
        Err(UnixSocketError::AlreadyConnected)
    );
    // Completed once.
    assert_eq!(
        fixture.complete(host, Err(UnixSocketError::ConnectionReset)),
        Err(UnixSocketError::NotConnected)
    );

    // A bound socket connects from its port.
    let bound = fixture.create(SocketType::Stream);
    fixture.bind(bound, &vsock(1024)).unwrap();
    let host = fixture.connect_to_host(connector, bound, 5000);
    assert_eq!(fixture.name(host, true), Ok(guest_vsock_name(1024)));
    assert_eq!(fixture.name(bound, false), Ok(guest_vsock_name(1024)));
}

#[test]
fn failed_vsock_connects_report_their_error_once() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    let client = fixture.create(SocketType::Stream);
    let host = fixture.connect_to_host(connector, client, 5000);
    let name = fixture.name(client, false);
    fixture.take_republished();
    assert_eq!(
        fixture.complete(host, Err(UnixSocketError::ConnectionReset)),
        Ok(())
    );
    assert!(fixture.take_republished().contains(&client));
    // Writable, with its error, and not hung up, as in Linux.
    assert_eq!(
        fixture.readiness(client),
        ReadinessFlags::ERROR | ReadinessFlags::WRITE
    );
    assert_eq!(
        fixture.take_error(client),
        Some(UnixSocketError::ConnectionReset)
    );
    assert_eq!(fixture.take_error(client), None);
    assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
    // Unconnected, and still bound; the connector's socket no longer reaches
    // it.
    assert_eq!(fixture.name(client, false), name);
    assert_eq!(
        fixture.name(client, true),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(fixture.name(host, true), name);
    fixture.close(host);
    assert_eq!(fixture.take_error(client), None);

    // It connects again; a connect reports a pending error first.
    let host = fixture.connect_to_host(connector, client, 5000);
    assert_eq!(fixture.name(host, true), name);
    assert_eq!(
        fixture.complete(host, Err(UnixSocketError::TimedOut)),
        Ok(())
    );
    assert_eq!(
        fixture.connect_vsock(client, &host_port(5000)),
        Err(UnixSocketError::TimedOut)
    );
    assert_eq!(fixture.take_error(client), None);
    let host = fixture.connect_to_host(connector, client, 5000);
    assert_eq!(fixture.complete(host, Ok(())), Ok(()));
    assert_eq!(fixture.send(client, b"x").unwrap(), Ok(1));
}

#[test]
fn closing_either_end_ends_a_vsock_connect() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    // The guest's close hangs up the connector's socket.
    let client = fixture.create(SocketType::Stream);
    let host = fixture.connect_to_host(connector, client, 5000);
    fixture.close(client);
    assert!(fixture.readiness(host).contains(ReadinessFlags::CLOSED));
    assert_eq!(
        fixture.complete(host, Ok(())),
        Err(UnixSocketError::NotConnected)
    );
    fixture.close(host);

    // The connector's socket's close fails the connect.
    let client = fixture.create(SocketType::Stream);
    let host = fixture.connect_to_host(connector, client, 5000);
    fixture.close(host);
    assert!(fixture.readiness(client).contains(ReadinessFlags::ERROR));
    assert_eq!(
        fixture.take_error(client),
        Some(UnixSocketError::ConnectionReset)
    );

    // So does the connector's, before it accepts; then no connect reaches
    // the host.
    assert_eq!(
        fixture.connect_vsock(client, &host_port(5000)),
        Ok(SocketConnectionStatus::Connecting)
    );
    fixture.close(connector);
    assert_eq!(
        fixture.connect_vsock(client, &host_port(5000)),
        Err(UnixSocketError::ConnectionReset)
    );
    assert_eq!(
        fixture.connect_vsock(client, &host_port(5000)),
        Err(UnixSocketError::Unreachable)
    );
    assert_eq!(fixture.queued(), (0, 0));
}

#[test]
fn full_host_connectors_refuse_connects_at_once() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(0);
    let first = fixture.create(SocketType::Stream);
    assert_eq!(
        fixture.connect_vsock(first, &host_port(5000)),
        Ok(SocketConnectionStatus::Connecting)
    );
    let second = fixture.create(SocketType::Stream);
    assert_eq!(
        connect(&fixture.process, second, &host_port(5000), USER),
        Err(BrokerError::ResourceExhausted)
    );
    assert_eq!(
        fixture.readiness(second) & ReadinessFlags::ERROR,
        ReadinessFlags::default()
    );
    fixture.accept(connector).unwrap().unwrap();
    let host = fixture.connect_to_host(connector, second, 5000);
    assert_eq!(fixture.complete(host, Ok(())), Ok(()));
}

#[test]
fn unconnected_vsock_sockets_are_writable_and_unix_ones_hung_up() {
    let fixture = Fixture::new();
    let bound = fixture.create(SocketType::Stream);
    fixture.bind(bound, &vsock(1024)).unwrap();
    assert_eq!(fixture.readiness(bound), ReadinessFlags::WRITE);
    // So is one created as a vsock socket, before it has a name, and after a
    // connect that named none.
    let created = create_vsock(
        &fixture.process,
        FileOpenFlags::NONE,
        &fixture.readiness_sink,
    )
    .unwrap();
    assert_eq!(fixture.readiness(created), ReadinessFlags::WRITE);
    assert_eq!(
        fixture.connect_vsock(created, &host_port(1024)),
        Err(UnixSocketError::Unreachable)
    );
    assert_eq!(fixture.name(created, false), Ok(UnixSocketName::Unnamed));
    assert_eq!(fixture.readiness(created), ReadinessFlags::WRITE);
    // Unix sockets, named or not, are hung up until they connect.
    let named = fixture.create(SocketType::Stream);
    fixture.bind(named, &abstract_name(b"unix")).unwrap();
    let unnamed = fixture.create(SocketType::Stream);
    for socket in [named, unnamed] {
        assert_eq!(
            fixture.readiness(socket),
            ReadinessFlags::WRITE | ReadinessFlags::CLOSED
        );
    }
}

#[test]
fn cancelled_vsock_connects_leave_the_socket_bound_and_hang_up_the_connector() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    let client = fixture.create(SocketType::Stream);
    let host = fixture.connect_to_host(connector, client, 5000);
    let name = fixture.name(client, false);
    fixture.take_republished();
    assert_eq!(
        cancel_vsock_connect(&fixture.process, client).unwrap(),
        Ok(())
    );
    assert!(fixture.take_republished().contains(&client));
    // Unconnected, still bound, with no error.
    assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
    assert_eq!(fixture.name(client, false), name);
    assert_eq!(
        fixture.name(client, true),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(fixture.take_error(client), None);
    // The connector's socket sees the hang-up; its completion is too late,
    // and changes nothing.
    assert!(fixture.readiness(host).contains(ReadinessFlags::CLOSED));
    for result in [Ok(()), Err(UnixSocketError::ConnectionReset)] {
        assert_eq!(
            fixture.complete(host, result),
            Err(UnixSocketError::NotConnected)
        );
    }
    assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
    assert_eq!(fixture.take_error(client), None);
    fixture.close(host);
    // Nothing more to cancel.
    assert_eq!(
        cancel_vsock_connect(&fixture.process, client).unwrap(),
        Ok(())
    );

    // It connects again, from its port.
    let host = fixture.connect_to_host(connector, client, 5000);
    assert_eq!(fixture.name(host, true), name);
    assert_eq!(fixture.complete(host, Ok(())), Ok(()));
    // A completed connect is not cancelled; a failed one reports its error.
    assert_eq!(
        cancel_vsock_connect(&fixture.process, client).unwrap(),
        Err(UnixSocketError::AlreadyConnected)
    );
    assert_eq!(fixture.send(client, b"x").unwrap(), Ok(1));
    // As a check reports them: a refusal stays pending, a timeout does not.
    let failed = fixture.create(SocketType::Stream);
    for error in [UnixSocketError::ConnectionReset, UnixSocketError::TimedOut] {
        let host = fixture.connect_to_host(connector, failed, 5000);
        assert_eq!(fixture.complete(host, Err(error)), Ok(()));
        assert_eq!(
            cancel_vsock_connect(&fixture.process, failed).unwrap(),
            Err(error)
        );
        let pending = (error == UnixSocketError::ConnectionReset).then_some(error);
        assert_eq!(fixture.take_error(failed), pending);
    }
}

#[test]
fn checks_report_vsock_connects_as_a_blocking_wait_sees_them() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    let client = fixture.create(SocketType::Stream);
    let check = |handle| check_connect(&fixture.process, handle).unwrap();
    assert_eq!(check(client), Ok(SocketConnectionStatus::Unconnected));
    let host = fixture.connect_to_host(connector, client, 5000);
    assert_eq!(check(client), Ok(SocketConnectionStatus::Connecting));
    assert_eq!(
        fixture.complete(host, Err(UnixSocketError::ConnectionReset)),
        Ok(())
    );
    // A refusal stays pending, for `SO_ERROR`, as in Linux.
    for _ in 0..2 {
        assert_eq!(check(client), Err(UnixSocketError::ConnectionReset));
        assert_eq!(
            fixture.readiness(client),
            ReadinessFlags::ERROR | ReadinessFlags::WRITE
        );
    }
    assert_eq!(
        fixture.take_error(client),
        Some(UnixSocketError::ConnectionReset)
    );
    assert_eq!(check(client), Ok(SocketConnectionStatus::Unconnected));

    // Linux's blocking connect times out itself, leaving no error.
    let host = fixture.connect_to_host(connector, client, 5000);
    assert_eq!(
        fixture.complete(host, Err(UnixSocketError::TimedOut)),
        Ok(())
    );
    fixture.take_republished();
    assert_eq!(check(client), Err(UnixSocketError::TimedOut));
    assert!(fixture.take_republished().contains(&client));
    assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
    assert_eq!(fixture.take_error(client), None);

    let host = fixture.connect_to_host(connector, client, 5000);
    assert_eq!(fixture.complete(host, Ok(())), Ok(()));
    assert_eq!(check(client), Ok(SocketConnectionStatus::Connected));
    assert_eq!(check(connector), Err(UnixSocketError::InvalidArgument));
}

#[test]
fn stale_hang_ups_leave_cancelled_sockets_and_their_next_connects_alone() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    let client = fixture.create(SocketType::Stream);
    let stale_host = fixture.connect_to_host(connector, client, 5000);
    let guest = fixture.socket(client).upgrade().unwrap();
    let stale = fixture.socket(stale_host).upgrade().unwrap();
    assert_eq!(
        cancel_vsock_connect(&fixture.process, client).unwrap(),
        Ok(())
    );
    // The connector's socket closing, having read its peer before the
    // cancel, hangs up afterwards: the cancelled socket stays unconnected.
    guest.hang_up(&stale);
    assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
    assert_eq!(fixture.take_error(client), None);

    // Nor does it fail the next attempt, or end its connection.
    let host = fixture.connect_to_host(connector, client, 5000);
    guest.hang_up(&stale);
    assert_eq!(fixture.readiness(client), ReadinessFlags::default());
    assert_eq!(fixture.complete(host, Ok(())), Ok(()));
    guest.hang_up(&stale);
    fixture.close(stale_host);
    drop(stale);
    assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
    assert_eq!(fixture.send(client, b"x").unwrap(), Ok(1));
    assert_eq!(fixture.receive_data(host, 8), b"x");
    assert_eq!(fixture.send(host, b"y").unwrap(), Ok(1));
    assert_eq!(fixture.receive_data(client, 8), b"y");
    assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
    assert_eq!(fixture.readiness(host), ReadinessFlags::WRITE);
}

#[test]
fn cancels_racing_the_connectors_completion_and_close_leave_the_socket_usable() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    for round in 0..2000 {
        let client = fixture.create(SocketType::Stream);
        let host = fixture.connect_to_host(connector, client, 5000);
        let barrier = std::sync::Barrier::new(2);
        let cancelled = std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                let result = if round % 2 == 0 {
                    Ok(())
                } else {
                    Err(UnixSocketError::ConnectionReset)
                };
                let _ = fixture.complete(host, result);
                fixture.close(host);
            });
            barrier.wait();
            cancel_vsock_connect(&fixture.process, client).unwrap()
        });
        match cancelled {
            // The connection completed, and then its peer closed.
            Err(UnixSocketError::AlreadyConnected) => assert_eq!(
                fixture.readiness(client),
                ReadinessFlags::READ
                    | ReadinessFlags::WRITE
                    | ReadinessFlags::HANGUP
                    | ReadinessFlags::CLOSED,
                "round {round}"
            ),
            Ok(()) | Err(UnixSocketError::ConnectionReset) => {
                // A failure stays pending; a cancel leaves no error.
                let error = cancelled.err();
                let readiness = if error.is_some() {
                    ReadinessFlags::ERROR | ReadinessFlags::WRITE
                } else {
                    ReadinessFlags::WRITE
                };
                assert_eq!(fixture.readiness(client), readiness, "round {round}");
                assert_eq!(fixture.take_error(client), error);
                // It connects again, and carries data both ways.
                let host = fixture.connect_to_host(connector, client, 5000);
                assert_eq!(fixture.complete(host, Ok(())), Ok(()));
                assert_eq!(fixture.send(client, b"x").unwrap(), Ok(1));
                assert_eq!(fixture.receive_data(host, 8), b"x");
                assert_eq!(fixture.send(host, b"y").unwrap(), Ok(1));
                assert_eq!(fixture.receive_data(client, 8), b"y");
                assert_eq!(fixture.readiness(client), ReadinessFlags::WRITE);
                fixture.close(host);
            }
            Err(error) => panic!("round {round}: {error:?}"),
        }
        fixture.close(client);
    }
}

/// How a test ends a vsock connect without connecting.
#[derive(Clone, Copy, Debug)]
enum ConnectEnd {
    Failed,
    Cancelled,
    ConnectorSocketClosed,
}

#[test]
fn data_queued_while_connecting_does_not_reach_a_later_connection() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    for end in [
        ConnectEnd::Failed,
        ConnectEnd::Cancelled,
        ConnectEnd::ConnectorSocketClosed,
    ] {
        let client = fixture.create(SocketType::Stream);
        let host = fixture.connect_to_host(connector, client, 5000);
        assert_eq!(fixture.send(host, b"stale").unwrap(), Ok(5), "{end:?}");
        assert_ne!(fixture.queued(), (0, 0), "{end:?}");
        match end {
            ConnectEnd::Failed => assert_eq!(
                fixture.complete(host, Err(UnixSocketError::ConnectionReset)),
                Ok(())
            ),
            ConnectEnd::Cancelled => assert_eq!(
                cancel_vsock_connect(&fixture.process, client).unwrap(),
                Ok(())
            ),
            ConnectEnd::ConnectorSocketClosed => fixture.close(host),
        }
        // Discarded, and its charge refunded.
        assert_eq!(fixture.queued(), (0, 0), "{end:?}");
        fixture.take_error(client);

        let host = fixture.connect_to_host(connector, client, 5000);
        assert_eq!(fixture.complete(host, Ok(())), Ok(()), "{end:?}");
        assert_eq!(fixture.send(host, b"new").unwrap(), Ok(3), "{end:?}");
        assert_eq!(fixture.receive_data(client, 16), b"new", "{end:?}");
        assert_eq!(
            fixture.receive(client, 16),
            Err(BrokerError::WouldBlock),
            "{end:?}"
        );
    }
}

#[test]
fn connecting_sockets_receive_data_queued_for_them_once_connected() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    let client = fixture.create(SocketType::Stream);
    let host = fixture.connect_to_host(connector, client, 5000);
    assert_eq!(fixture.send(host, b"early").unwrap(), Ok(5));
    // Not readable while connecting.
    assert_eq!(fixture.readiness(client), ReadinessFlags::default());
    assert_eq!(
        fixture.receive(client, 16).unwrap(),
        Err(UnixSocketError::NotConnected)
    );
    assert_eq!(fixture.complete(host, Ok(())), Ok(()));
    assert_eq!(
        fixture.readiness(client),
        ReadinessFlags::READ | ReadinessFlags::WRITE
    );
    assert_eq!(fixture.send(host, b"late").unwrap(), Ok(4));
    assert_eq!(fixture.receive_data(client, 16), b"earlylate");
}

#[test]
fn failed_completions_end_the_connectors_socket() {
    let fixture = Fixture::new();
    let connector = fixture.host_connector(8);
    let client = fixture.create(SocketType::Stream);
    let host = fixture.connect_to_host(connector, client, 5000);
    fixture.take_republished();
    assert_eq!(
        fixture.complete(host, Err(UnixSocketError::ConnectionReset)),
        Ok(())
    );
    assert!(fixture.take_republished().contains(&host));
    assert_eq!(
        fixture.send(host, b"x").unwrap(),
        Err(UnixSocketError::BrokenPipe)
    );
    assert_eq!(
        fixture.receive(host, 8).unwrap(),
        Ok(Message {
            source: Some(fixture.name(client, false).unwrap()),
            ..Message::default()
        })
    );
    assert!(
        fixture
            .readiness(host)
            .contains(ReadinessFlags::READ | ReadinessFlags::HANGUP | ReadinessFlags::CLOSED)
    );
}
