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
use core::time::Duration;
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
        let fs = Resolver::<TestPlatform, _>::new(InMem::<TestPlatform>::new(
            InodeAllocator::standalone(),
        ));
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
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
        receive(&self.process, handle, capacity, false, false)
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
            self.process.core.unix_sockets.lock().queued,
            self.process.unix_socket_bytes.load(Ordering::Relaxed),
        )
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

    let peeked = receive(&fixture.process, second, 3, true, false)
        .unwrap()
        .unwrap();
    assert_eq!(peeked.data, b"hel");
    assert_eq!(peeked.source, UnixSocketName::Unnamed);
    assert_eq!(fixture.receive_data(second, 3), b"hel");
    assert_eq!(fixture.receive_data(second, 10), b"lo");
    assert_eq!(fixture.receive(second, 10), Err(BrokerError::WouldBlock));
    assert_eq!(fixture.send(first, b""), Ok(Ok(0)));

    assert_eq!(fixture.send(second, b"back").unwrap(), Ok(4));
    assert_eq!(fixture.receive_data(first, 10), b"back");
    assert_eq!(fixture.queued(), (0, 0));
}

#[test]
fn status_flags_belong_to_the_shared_object() {
    let fixture = Fixture::new();
    let (first, second) = create_pair(
        &fixture.process,
        SocketType::Datagram,
        FileOpenFlags::NONBLOCKING,
        &fixture.readiness_sink,
    )
    .unwrap();
    assert_eq!(
        fixture.receive(first, 1),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    assert_eq!(
        fixture.process.get_status_flags(second).unwrap(),
        FileStatusFlags {
            access: FileAccessMode::ReadWrite,
            flags: FileOpenFlags::NONBLOCKING,
        }
    );
    assert_eq!(
        create(
            &fixture.process,
            SocketType::Stream,
            FileOpenFlags::CREATE,
            &fixture.readiness_sink,
        ),
        Err(BrokerError::UnsupportedOperation)
    );
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
        UnixSocketName::Abstract(b"client".to_vec())
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

    let (file, _) = crate::fs::open_node(
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
    fixture.close(listener);
    assert_eq!(fixture.queued(), (0, 0));
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
fn a_read_shut_datagram_socket_ends_only_blocking_receives() {
    let fixture = Fixture::new();
    let (first, second) = fixture.pair(SocketType::Datagram);
    assert_eq!(fixture.send(second, b"queued").unwrap(), Ok(6));
    shutdown(&fixture.process, first, ShutdownMode::Read)
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture.send(second, b"x").unwrap(),
        Err(UnixSocketError::BrokenPipe)
    );
    assert_eq!(
        receive(&fixture.process, first, 8, false, true)
            .unwrap()
            .unwrap()
            .data,
        b"queued"
    );
    assert_eq!(
        receive(&fixture.process, first, 8, false, true),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    assert_eq!(fixture.receive(first, 8), Ok(Ok(Received::default())));
    // Shutting down the peer's sending direction leaves this socket open.
    shutdown(&fixture.process, first, ShutdownMode::Write)
        .unwrap()
        .unwrap();
    assert_eq!(fixture.receive(second, 8), Err(BrokerError::WouldBlock));
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
            source: path("/named").name(),
        }
    );
    assert_eq!(
        fixture.receive(receiver, 8).unwrap().unwrap(),
        Received::default()
    );
    let peeked = receive(&fixture.process, receiver, 8, true, false)
        .unwrap()
        .unwrap();
    assert_eq!(peeked.data, b"defgh");
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
        receiver_address.name()
    );
    assert_eq!(
        name(&fixture.process, receiver, true).unwrap(),
        Ok(peer_address.name())
    );

    fixture.close(peer);
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
        receive(&fixture.process, receiver, 1, false, true),
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
    assert!(fixture.process.core.unix_sockets.lock().sockets.is_empty());
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
        receive(&child, duplicated, 8, false, false)
            .unwrap()
            .unwrap()
            .data,
        b"child"
    );
    child.close_object_reference(duplicated).unwrap();
    assert_eq!(fixture.receive_data(second, 8), b"");
}

#[test]
fn options_are_stored_with_the_socket() {
    let fixture = Fixture::new();
    let socket = fixture.create(SocketType::Datagram);
    set_option(
        &fixture.process,
        socket,
        UnixSocketOption::ReceiveTimeout(Some(Duration::from_secs(2))),
    )
    .unwrap();
    let (socket_type, options) = options(&fixture.process, socket).unwrap();
    assert_eq!(socket_type, SocketType::Datagram);
    assert_eq!(options.receive_timeout, Some(Duration::from_secs(2)));
}
