// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;
use std::vec::Vec;

use litebox_broker_protocol::fs::SetStatusFlagsRequest;
use litebox_broker_protocol::socket::ReceiveFlags;
use litebox_broker_protocol::vsock::{VMADDR_CID_ANY, VMADDR_CID_HOST, VMADDR_PORT_ANY};

use super::*;
use crate::readiness::tests::TestReadinessSink;
use crate::socket::UnsupportedSocketProvider;
use crate::socket::tests::process_reserved_sockets;
use crate::{BrokerCore, CallerCredential, PolicyEngine, VsockPolicy};

const HOST: VsockAddress = VsockAddress {
    cid: VMADDR_CID_HOST,
    port: 5000,
};

/// State shared by a [`TestVsockProvider`] and its sockets.
#[derive(Default)]
struct ProviderState {
    /// Every operation a socket received, in order.
    calls: StdMutex<Vec<&'static str>>,
    /// Peers of the connections listeners accept, oldest first.
    pending: StdMutex<VecDeque<VsockAddress>>,
    /// Every socket created or accepted, which the provider retains.
    sockets: StdMutex<Vec<Arc<TestVsockSocket>>>,
}

#[derive(Default)]
struct TestVsockProvider(Arc<ProviderState>);

impl TestVsockProvider {
    fn socket(&self, index: usize) -> Arc<TestVsockSocket> {
        Arc::clone(&self.0.sockets.lock().unwrap()[index])
    }

    fn calls(&self) -> Vec<&'static str> {
        self.0.calls.lock().unwrap().clone()
    }

    fn socket_count(&self) -> usize {
        self.0.sockets.lock().unwrap().len()
    }
}

impl VsockProvider for TestVsockProvider {
    fn create(&self, readiness: ReadinessRegistration) -> Result<Arc<dyn PlatformVsockSocket>> {
        Ok(TestVsockSocket::new(&self.0, readiness, None))
    }
}

/// A socket whose replies the test sets, and which records its calls.
struct TestVsockSocket {
    provider: Arc<ProviderState>,
    readiness: ReadinessRegistration,
    snapshot: StdMutex<ReadinessFlags>,
    local: StdMutex<Option<VsockAddress>>,
    peer: Option<VsockAddress>,
    /// What an accept fails with, if anything.
    accept_failure: StdMutex<Option<SocketError>>,
    connect: StdMutex<SocketOutcome<SocketConnectionStatus>>,
    check_connect: StdMutex<SocketOutcome<SocketConnectionStatus>>,
    /// What a send or receive reports, or `None` if it would block.
    transferred: StdMutex<Option<usize>>,
    retired: AtomicUsize,
}

impl TestVsockSocket {
    fn new(
        provider: &Arc<ProviderState>,
        readiness: ReadinessRegistration,
        peer: Option<VsockAddress>,
    ) -> Arc<Self> {
        let socket = Arc::new(Self {
            provider: Arc::clone(provider),
            readiness,
            snapshot: StdMutex::new(ReadinessFlags::default()),
            local: StdMutex::new(None),
            peer,
            accept_failure: StdMutex::new(None),
            connect: StdMutex::new(SocketOutcome::Completed(SocketConnectionStatus::Connecting)),
            check_connect: StdMutex::new(SocketOutcome::Completed(
                SocketConnectionStatus::Connecting,
            )),
            transferred: StdMutex::new(None),
            retired: AtomicUsize::new(0),
        });
        // An unconnected socket is writable.
        socket.set_readiness(ReadinessFlags::WRITE);
        provider.sockets.lock().unwrap().push(Arc::clone(&socket));
        socket
    }

    fn set_readiness(&self, readiness: ReadinessFlags) {
        *self.snapshot.lock().unwrap() = readiness;
        self.readiness.publish(readiness);
    }

    fn call(&self, name: &'static str) {
        self.provider.calls.lock().unwrap().push(name);
    }
}

impl PlatformVsockSocket for TestVsockSocket {
    fn bind(&self, address: VsockAddress) -> Result<SocketOutcome<()>> {
        self.call("bind");
        *self.local.lock().unwrap() = Some(address);
        Ok(SocketOutcome::Completed(()))
    }

    fn listen(&self, _backlog: u32) -> Result<SocketOutcome<()>> {
        self.call("listen");
        Ok(if self.local.lock().unwrap().is_some() {
            SocketOutcome::Completed(())
        } else {
            SocketOutcome::Failed(SocketError::InvalidArgument)
        })
    }

    fn accept(
        &self,
        readiness: ReadinessRegistration,
    ) -> Result<SocketOutcome<AcceptedPlatformVsockSocket>> {
        self.call("accept");
        if let Some(error) = *self.accept_failure.lock().unwrap() {
            return Ok(SocketOutcome::Failed(error));
        }
        let peer_address = self
            .provider
            .pending
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(BrokerError::WouldBlock)?;
        Ok(SocketOutcome::Completed(AcceptedPlatformVsockSocket {
            socket: TestVsockSocket::new(&self.provider, readiness, Some(peer_address)),
            peer_address,
        }))
    }

    fn connect(&self, _address: VsockAddress) -> Result<SocketOutcome<SocketConnectionStatus>> {
        self.call("connect");
        Ok(*self.connect.lock().unwrap())
    }

    fn check_connect(&self) -> Result<SocketOutcome<SocketConnectionStatus>> {
        self.call("check_connect");
        Ok(*self.check_connect.lock().unwrap())
    }

    fn cancel_connect(&self) -> Result<SocketOutcome<()>> {
        self.call("cancel_connect");
        Ok(SocketOutcome::Completed(()))
    }

    fn take_error(&self) -> Option<SocketError> {
        self.call("take_error");
        Some(SocketError::ConnectionReset)
    }

    fn send(&self, _data: &dyn WriteBuffer) -> Result<SocketOutcome<usize>> {
        self.call("send");
        let sent = self
            .transferred
            .lock()
            .unwrap()
            .ok_or(BrokerError::WouldBlock)?;
        Ok(SocketOutcome::Completed(sent))
    }

    fn receive(
        &self,
        _output: &mut dyn ReadBuffer,
    ) -> Result<SocketOutcome<PlatformStreamReceive>> {
        self.call("receive");
        let received = self
            .transferred
            .lock()
            .unwrap()
            .ok_or(BrokerError::WouldBlock)?;
        Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
            received,
        )))
    }

    fn shutdown(&self, _mode: ShutdownMode) -> Result<SocketOutcome<()>> {
        self.call("shutdown");
        Ok(SocketOutcome::Completed(()))
    }

    fn local_address(&self) -> Option<VsockAddress> {
        self.call("local_address");
        *self.local.lock().unwrap()
    }

    fn peer_address(&self) -> Option<VsockAddress> {
        self.call("peer_address");
        self.peer
    }

    fn readiness(&self) -> ReadinessFlags {
        *self.snapshot.lock().unwrap()
    }

    fn retire(&self) {
        self.retired.fetch_add(1, Ordering::Relaxed);
    }
}

fn test_broker(provider: &Arc<TestVsockProvider>) -> BrokerCore {
    test_broker_with_policy(VsockPolicy::any())
        .with_vsock_provider(Arc::clone(provider) as Arc<dyn VsockProvider>)
}

/// Returns a broker without a vsock provider whose policy is `vsock_policy`.
fn test_broker_with_policy(vsock_policy: VsockPolicy) -> BrokerCore {
    BrokerCore {
        policy: Arc::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_vsock_policy(vsock_policy),
        ),
        ..crate::socket::tests::test_broker(Arc::new(UnsupportedSocketProvider))
    }
}

fn new_process(broker: &BrokerCore) -> Arc<BrokerProcess> {
    broker
        .allocate_process(CallerCredential::Unauthenticated, None)
        .unwrap()
}

fn set_nonblocking(process: &BrokerProcess, handle: ObjectHandle, nonblocking: bool) {
    process
        .set_status_flags(SetStatusFlagsRequest {
            handle,
            mask: FileOpenFlags::NONBLOCKING,
            flags: if nonblocking {
                FileOpenFlags::NONBLOCKING
            } else {
                FileOpenFlags::NONE
            },
        })
        .unwrap();
}

/// Asserts that `process` holds no socket and no reference, and that `sink`
/// saw none.
fn assert_nothing_created(broker: &BrokerCore, process: &BrokerProcess, sink: &TestReadinessSink) {
    assert!(sink.published.lock().unwrap().is_empty());
    assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
    assert!(broker.references.read().is_empty());
    assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
    assert_eq!(process_reserved_sockets(process), 0);
}

#[test]
fn creating_without_a_provider_is_unsupported_whatever_the_policy() {
    for vsock_policy in [VsockPolicy::deny(), VsockPolicy::any()] {
        let broker = test_broker_with_policy(vsock_policy);
        let process = new_process(&broker);
        let sink = Arc::new(TestReadinessSink::default());

        assert_eq!(
            create(&process, FileOpenFlags::NONE, sink.clone()),
            Err(BrokerError::UnsupportedOperation)
        );
        assert_nothing_created(&broker, &process, &sink);
    }
}

#[test]
fn a_provider_reaches_every_clone_of_the_core() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker_with_policy(VsockPolicy::any());
    let clone = broker.clone();
    let process = new_process(&clone);
    let sink = || Arc::new(TestReadinessSink::default()) as Arc<dyn ReadinessSink>;
    assert_eq!(
        create(&process, FileOpenFlags::NONE, sink()),
        Err(BrokerError::UnsupportedOperation)
    );

    // A clone taken, and a process created, before the provider was installed
    // see it.
    let _broker = broker.with_vsock_provider(Arc::clone(&provider) as Arc<dyn VsockProvider>);
    assert!(create(&process, FileOpenFlags::NONE, sink()).is_ok());
    assert!(create(&new_process(&clone), FileOpenFlags::NONE, sink()).is_ok());
    assert_eq!(provider.socket_count(), 2);
}

#[test]
fn creating_without_the_policy_never_reaches_the_provider() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker_with_policy(VsockPolicy::deny())
        .with_vsock_provider(Arc::clone(&provider) as Arc<dyn VsockProvider>);
    let process = new_process(&broker);
    let sink = Arc::new(TestReadinessSink::default());

    assert_eq!(
        create(&process, FileOpenFlags::NONE, sink.clone()),
        Err(BrokerError::PolicyDenied)
    );
    assert_nothing_created(&broker, &process, &sink);
    assert_eq!(provider.socket_count(), 0);
}

#[test]
fn denied_connects_and_listens_never_reach_the_provider() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker_with_policy(
        VsockPolicy::deny()
            .with_connect_ports(HOST.port + 1..=HOST.port + 1)
            .with_listen_ports(HOST.port + 1..=HOST.port + 1),
    )
    .with_vsock_provider(Arc::clone(&provider) as Arc<dyn VsockProvider>);
    let process = new_process(&broker);
    let socket = create(
        &process,
        FileOpenFlags::NONE,
        Arc::new(TestReadinessSink::default()),
    )
    .unwrap();
    let allowed = VsockAddress {
        port: HOST.port + 1,
        ..HOST
    };

    assert_eq!(
        connect(&process, socket, HOST),
        Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
    );
    assert_eq!(provider.calls(), [] as [&str; 0]);
    assert_eq!(
        connect(&process, socket, allowed),
        Ok(SocketOutcome::Completed(SocketConnectionStatus::Connecting))
    );
    assert_eq!(provider.calls(), ["connect"]);

    // An unbound socket's listen fails as the provider says.
    assert_eq!(
        listen(&process, socket, 1),
        Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
    );
    assert_eq!(provider.calls(), ["connect", "local_address", "listen"]);
    // A bound one listens only on a port the policy allows.
    for (port, expected, calls) in [
        (
            HOST.port,
            SocketOutcome::Failed(SocketError::PolicyDenied),
            &["local_address"][..],
        ),
        (
            HOST.port + 1,
            SocketOutcome::Completed(()),
            &["local_address", "listen"],
        ),
    ] {
        let socket = create(
            &process,
            FileOpenFlags::NONE,
            Arc::new(TestReadinessSink::default()),
        )
        .unwrap();
        assert_eq!(
            bind(&process, socket, VsockAddress { port, ..HOST }),
            Ok(SocketOutcome::Completed(()))
        );
        provider.0.calls.lock().unwrap().clear();
        assert_eq!(listen(&process, socket, 1), Ok(expected));
        assert_eq!(provider.calls(), calls);
    }
}

#[test]
fn connects_to_other_cids_skip_the_policy() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker_with_policy(VsockPolicy::deny().with_listen_ports(0..=u32::MAX))
        .with_vsock_provider(Arc::clone(&provider) as Arc<dyn VsockProvider>);
    let process = new_process(&broker);
    let socket = create(
        &process,
        FileOpenFlags::NONE,
        Arc::new(TestReadinessSink::default()),
    )
    .unwrap();
    let platform = provider.socket(0);
    let elsewhere = VsockAddress {
        cid: VMADDR_CID_ANY,
        port: VMADDR_PORT_ANY,
    };

    // The socket's state decides, as the provider reports it.
    for error in [
        SocketError::AlreadyConnected,
        SocketError::NetworkUnreachable,
    ] {
        *platform.connect.lock().unwrap() = SocketOutcome::Failed(error);
        assert_eq!(
            connect(&process, socket, elsewhere),
            Ok(SocketOutcome::Failed(error))
        );
    }
    assert_eq!(provider.calls(), ["connect", "connect"]);
    // A provider that starts one breaks its contract.
    *platform.connect.lock().unwrap() =
        SocketOutcome::Completed(SocketConnectionStatus::Connecting);
    assert_eq!(
        connect(&process, socket, elsewhere),
        Err(BrokerError::Internal)
    );
    // The host stays denied.
    *platform.connect.lock().unwrap() = SocketOutcome::Failed(SocketError::AlreadyConnected);
    assert_eq!(
        connect(&process, socket, HOST),
        Ok(SocketOutcome::Failed(SocketError::PolicyDenied))
    );
    assert_eq!(provider.calls(), ["connect", "connect", "connect"]);
}

#[test]
fn operations_require_their_rights_and_a_vsock_handle() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker(&provider);
    let owner = new_process(&broker);
    let reader = new_process(&broker);
    let writer = new_process(&broker);
    let socket = create(
        &owner,
        FileOpenFlags::NONE,
        Arc::new(TestReadinessSink::default()),
    )
    .unwrap();
    let wait_only = owner
        .duplicate_object_reference_to(socket, &reader, ObjectRights::WAIT)
        .unwrap();
    let write_only = owner
        .duplicate_object_reference_to(socket, &writer, ObjectRights::WRITE)
        .unwrap();
    let sink = || Arc::new(TestReadinessSink::default()) as Arc<dyn ReadinessSink>;
    let mut buffer = [0u8; 4];

    let write_operations = |process: &BrokerProcess, handle| {
        [
            bind(process, handle, HOST).err(),
            listen(process, handle, 1).err(),
            connect(process, handle, HOST).err(),
            check_connect(process, handle).err(),
            cancel_connect(process, handle).err(),
            send(process, handle, &[1u8], SendFlags::NONE).err(),
            shutdown(process, handle, ShutdownMode::Both).err(),
        ]
    };
    let wait_operations = |process: &BrokerProcess, handle, buffer: &mut dyn ReadBuffer| {
        [
            accept(process, handle, FileOpenFlags::NONE, sink()).err(),
            receive(process, handle, buffer, ReceiveFlags::NONE).err(),
        ]
    };

    // Each operation needs its right, and fails without reaching the provider.
    assert_eq!(
        write_operations(&reader, wait_only),
        [Some(BrokerError::InvalidRights); 7]
    );
    assert_eq!(
        wait_operations(&writer, write_only, &mut buffer),
        [Some(BrokerError::InvalidRights); 2]
    );
    assert_eq!(provider.calls(), [] as [&str; 0]);

    // Either right reads the socket's names and pending error.
    for (process, handle) in [(&reader, wait_only), (&writer, write_only)] {
        assert_eq!(get_name(process, handle, false), Ok(None));
        assert_eq!(
            take_error(process, handle),
            Ok(Some(SocketError::ConnectionReset))
        );
    }
    *provider.socket(0).transferred.lock().unwrap() = Some(1);
    assert_eq!(write_operations(&writer, write_only), [None; 7]);
    // Nothing is pending to accept.
    assert_eq!(
        wait_operations(&reader, wait_only, &mut buffer),
        [Some(BrokerError::WouldBlock), None]
    );

    // Another kind of object, or another process's handle, is not a vsock
    // socket.
    let event = crate::event::create(&owner, 0, FileOpenFlags::NONE).unwrap();
    assert_eq!(
        connect(&owner, event, HOST),
        Err(BrokerError::InvalidRights)
    );
    assert_eq!(
        get_name(&owner, event, true),
        Err(BrokerError::InvalidRights)
    );
    assert_eq!(
        connect(&reader, socket, HOST),
        Err(BrokerError::UnknownObject)
    );
}

#[test]
fn readiness_reaches_every_reference_until_the_socket_retires() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker(&provider);
    let creator = new_process(&broker);
    let target = new_process(&broker);
    let creator_sink = Arc::new(TestReadinessSink::default());
    let socket = create(&creator, FileOpenFlags::NONE, creator_sink.clone()).unwrap();
    let platform = provider.socket(0);
    // The provider's initial publication reaches the creating reference.
    assert_eq!(
        *creator_sink.published.lock().unwrap(),
        [(socket, ReadinessFlags::WRITE)]
    );
    assert_eq!(creator.check_readiness(socket), Ok(ReadinessFlags::WRITE));

    let duplicate = creator
        .duplicate_object_reference_to(socket, &target, ObjectRights::all())
        .unwrap();
    let target_sink = Arc::new(TestReadinessSink::default());
    target
        .register_readiness(&(target_sink.clone() as Arc<dyn ReadinessSink>))
        .unwrap();
    let queue_sink = Arc::new(TestReadinessSink::default());
    let queue =
        crate::readiness_queue::create(&target, &(queue_sink.clone() as Arc<dyn ReadinessSink>))
            .unwrap();
    let interest = litebox_broker_protocol::readiness_queue::ReadinessQueueInterest {
        readiness: ReadinessFlags::READ,
        flags: litebox_broker_protocol::readiness_queue::ReadinessQueueEntryFlags::empty(),
        token: 7,
    };
    crate::readiness_queue::add(&target, queue, duplicate, 0, interest)
        .unwrap()
        .unwrap();
    queue_sink.republished.lock().unwrap().clear();

    // A publication reaches every reference and the queue watching one.
    platform.set_readiness(ReadinessFlags::READ | ReadinessFlags::WRITE);
    let readable = ReadinessFlags::READ | ReadinessFlags::WRITE;
    assert_eq!(
        creator_sink.published.lock().unwrap().last(),
        Some(&(socket, readable))
    );
    assert_eq!(
        *target_sink.published.lock().unwrap(),
        [(duplicate, readable)]
    );
    assert_eq!(
        *queue_sink.republished.lock().unwrap(),
        [(queue, ReadinessFlags::READ)]
    );
    assert_eq!(target.check_readiness(duplicate), Ok(readable));
    // A republication wakes waiters although the flags are unchanged.
    platform.readiness.republish(readable);
    assert_eq!(
        *creator_sink.republished.lock().unwrap(),
        [(socket, readable)]
    );
    assert_eq!(
        *target_sink.republished.lock().unwrap(),
        [(duplicate, readable)]
    );

    // The duplicate keeps the socket, still charged to its creator, after
    // the creator releases its references.
    creator.cleanup(true);
    assert_eq!(*creator_sink.retired.lock().unwrap(), [socket]);
    assert_eq!(platform.retired.load(Ordering::Relaxed), 0);
    assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
    platform.set_readiness(ReadinessFlags::WRITE);
    assert_eq!(
        target_sink.published.lock().unwrap().last(),
        Some(&(duplicate, ReadinessFlags::WRITE))
    );

    // Closing the last reference retires the socket once, although the
    // provider retains it, and its later publications go nowhere.
    target.close_object_reference(queue).unwrap();
    target.close_object_reference(duplicate).unwrap();
    assert_eq!(platform.retired.load(Ordering::Relaxed), 1);
    assert_eq!(*target_sink.retired.lock().unwrap(), [duplicate]);
    let published = target_sink.published.lock().unwrap().len();
    platform.set_readiness(ReadinessFlags::READ);
    assert_eq!(target_sink.published.lock().unwrap().len(), published);
    assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 0);
}

#[test]
fn accepted_sockets_get_handles_and_are_charged_to_the_listener() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker(&provider);
    let owner = new_process(&broker);
    let sharer = new_process(&broker);
    let listener = create(
        &owner,
        FileOpenFlags::NONE,
        Arc::new(TestReadinessSink::default()),
    )
    .unwrap();
    assert_eq!(
        bind(&owner, listener, HOST),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        listen(&owner, listener, 2),
        Ok(SocketOutcome::Completed(()))
    );
    let duplicate = owner
        .duplicate_object_reference_to(listener, &sharer, ObjectRights::all())
        .unwrap();

    // With nothing pending, accept waits unless the listener is non-blocking,
    // and keeps nothing.
    let sink = Arc::new(TestReadinessSink::default());
    assert_eq!(
        accept(&sharer, duplicate, FileOpenFlags::NONE, sink.clone()),
        Err(BrokerError::WouldBlock)
    );
    set_nonblocking(&owner, listener, true);
    assert_eq!(
        accept(&sharer, duplicate, FileOpenFlags::NONE, sink.clone()),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    assert_eq!(sink.retired.lock().unwrap().len(), 2);
    assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
    assert_eq!(process_reserved_sockets(&owner), 1);
    assert_eq!(provider.socket_count(), 1);

    // An accept through the duplicate gets a handle there, with its own
    // status flags, charged to the listener's process.
    provider.0.pending.lock().unwrap().push_back(HOST);
    let sink = Arc::new(TestReadinessSink::default());
    let SocketOutcome::Completed(accepted) =
        accept(&sharer, duplicate, FileOpenFlags::NONE, sink.clone()).unwrap()
    else {
        panic!("accept failed");
    };
    assert_eq!(accepted.peer_address, HOST);
    assert_eq!(get_name(&sharer, accepted.handle, true), Ok(Some(HOST)));
    assert!(
        !sharer
            .get_status_flags(accepted.handle)
            .unwrap()
            .flags
            .contains(FileOpenFlags::NONBLOCKING)
    );
    assert_eq!(
        *sink.published.lock().unwrap(),
        [(accepted.handle, ReadinessFlags::WRITE)]
    );
    assert_eq!(process_reserved_sockets(&owner), 2);
    assert_eq!(process_reserved_sockets(&sharer), 0);

    // The accepted socket outlives its listener, still charged to the
    // listener's process.
    let accepted_platform = provider.socket(1);
    owner.close_object_reference(listener).unwrap();
    sharer.close_object_reference(duplicate).unwrap();
    assert_eq!(provider.socket(0).retired.load(Ordering::Relaxed), 1);
    assert_eq!(accepted_platform.retired.load(Ordering::Relaxed), 0);
    assert_eq!(process_reserved_sockets(&owner), 1);
    sharer.close_object_reference(accepted.handle).unwrap();
    assert_eq!(accepted_platform.retired.load(Ordering::Relaxed), 1);
    assert_eq!(process_reserved_sockets(&owner), 0);
}

#[test]
fn failed_accepts_release_what_they_reserved() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker(&provider);
    let owner = new_process(&broker);
    let listener = create(
        &owner,
        FileOpenFlags::NONE,
        Arc::new(TestReadinessSink::default()),
    )
    .unwrap();
    assert_eq!(
        bind(&owner, listener, HOST),
        Ok(SocketOutcome::Completed(()))
    );
    assert_eq!(
        listen(&owner, listener, 2),
        Ok(SocketOutcome::Completed(()))
    );
    *provider.socket(0).accept_failure.lock().unwrap() = Some(SocketError::InvalidArgument);
    let references = broker.references.read().len();

    // More failures than the socket quota allows sockets.
    for _ in 0..=broker.limits.max_sockets {
        let sink = Arc::new(TestReadinessSink::default());
        assert_eq!(
            accept(&owner, listener, FileOpenFlags::NONE, sink.clone()),
            Ok(SocketOutcome::Failed(SocketError::InvalidArgument))
        );
        assert!(sink.published.lock().unwrap().is_empty());
        assert_eq!(sink.retired.lock().unwrap().len(), 1);
        assert_eq!(broker.pending_references.load(Ordering::Relaxed), 0);
        assert_eq!(broker.references.read().len(), references);
        assert_eq!(broker.reserved_sockets.load(Ordering::Relaxed), 1);
        assert_eq!(process_reserved_sockets(&owner), 1);
    }
    assert_eq!(provider.socket_count(), 1);
    assert_eq!(provider.socket(0).retired.load(Ordering::Relaxed), 0);

    // The listener accepts once the provider does.
    *provider.socket(0).accept_failure.lock().unwrap() = None;
    provider.0.pending.lock().unwrap().push_back(HOST);
    assert!(matches!(
        accept(
            &owner,
            listener,
            FileOpenFlags::NONE,
            Arc::new(TestReadinessSink::default())
        ),
        Ok(SocketOutcome::Completed(_))
    ));
    assert_eq!(process_reserved_sockets(&owner), 2);
}

#[test]
fn transfers_report_would_block_by_the_shared_status_flags() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker(&provider);
    let process = new_process(&broker);
    let socket = create(
        &process,
        FileOpenFlags::NONBLOCKING,
        Arc::new(TestReadinessSink::default()),
    )
    .unwrap();
    let mut buffer = [0u8; 8];

    assert_eq!(
        send(&process, socket, &[1u8; 8], SendFlags::NONE),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    assert_eq!(
        receive(&process, socket, &mut buffer, ReceiveFlags::NONE),
        Err(BrokerError::NonBlockingWouldBlock)
    );
    set_nonblocking(&process, socket, false);
    assert_eq!(
        send(&process, socket, &[1u8; 8], SendFlags::NONE),
        Err(BrokerError::WouldBlock)
    );
    assert_eq!(
        receive(&process, socket, &mut buffer, ReceiveFlags::NONE),
        Err(BrokerError::WouldBlock)
    );

    *provider.socket(0).transferred.lock().unwrap() = Some(3);
    assert_eq!(
        send(&process, socket, &[1u8; 8], SendFlags::NONE),
        Ok(SocketOutcome::Completed(3))
    );
    assert_eq!(
        receive(&process, socket, &mut buffer, ReceiveFlags::NONE),
        Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(3)))
    );
}

#[test]
fn unsupported_requests_never_reach_the_provider() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker(&provider);
    let process = new_process(&broker);
    let sink = || Arc::new(TestReadinessSink::default()) as Arc<dyn ReadinessSink>;
    assert_eq!(
        create(&process, FileOpenFlags::CREATE, sink()),
        Err(BrokerError::UnsupportedOperation)
    );
    assert_eq!(provider.socket_count(), 0);
    let socket = create(&process, FileOpenFlags::NONE, sink()).unwrap();
    let oversized = alloc::vec![0u8; MAX_SOCKET_TRANSFER_SIZE as usize + 1];
    let mut oversized_output = oversized.clone();
    let mut output = [0u8; 4];

    for result in [
        accept(&process, socket, FileOpenFlags::CREATE, sink()).map(drop),
        listen(&process, socket, MAX_VSOCK_LISTEN_BACKLOG + 1).map(drop),
        send(&process, socket, &[1u8], SendFlags(1)).map(drop),
        send(&process, socket, &oversized, SendFlags::NONE).map(drop),
        receive(&process, socket, &mut output, ReceiveFlags::PEEK).map(drop),
        receive(&process, socket, &mut oversized_output, ReceiveFlags::NONE).map(drop),
        shutdown(&process, socket, ShutdownMode::Abort).map(drop),
        shutdown(&process, socket, ShutdownMode::StopListening).map(drop),
    ] {
        assert_eq!(result, Err(BrokerError::UnsupportedOperation));
    }
    assert_eq!(provider.calls(), [] as [&str; 0]);
}

#[test]
fn provider_results_outside_the_contract_are_internal_errors() {
    let provider = Arc::new(TestVsockProvider::default());
    let broker = test_broker(&provider);
    let process = new_process(&broker);
    let socket = create(
        &process,
        FileOpenFlags::NONE,
        Arc::new(TestReadinessSink::default()),
    )
    .unwrap();
    let platform = provider.socket(0);

    // A connect reports progress, and its failure as an outcome.
    for (status, result) in [
        (
            SocketConnectionStatus::Connected,
            Ok(SocketOutcome::Completed(SocketConnectionStatus::Connected)),
        ),
        (
            SocketConnectionStatus::Unconnected,
            Err(BrokerError::Internal),
        ),
        (
            SocketConnectionStatus::Failed(SocketError::TimedOut),
            Err(BrokerError::Internal),
        ),
    ] {
        *platform.connect.lock().unwrap() = SocketOutcome::Completed(status);
        assert_eq!(connect(&process, socket, HOST), result);
        *platform.check_connect.lock().unwrap() = SocketOutcome::Completed(status);
        assert_eq!(
            check_connect(&process, socket),
            if status == SocketConnectionStatus::Unconnected {
                Ok(SocketOutcome::Completed(status))
            } else {
                result
            }
        );
    }

    // A transfer moves no more than asked, and something unless asked for
    // nothing.
    let mut output = [0u8; 4];
    for (transferred, valid) in [(4, true), (5, false), (0, false)] {
        *platform.transferred.lock().unwrap() = Some(transferred);
        let sent = send(&process, socket, &[1u8; 4], SendFlags::NONE);
        let received = receive(&process, socket, &mut output, ReceiveFlags::NONE);
        if valid {
            assert_eq!(sent, Ok(SocketOutcome::Completed(transferred)));
            assert_eq!(
                received,
                Ok(SocketOutcome::Completed(PlatformStreamReceive::Received(
                    transferred
                )))
            );
        } else {
            assert_eq!(sent, Err(BrokerError::Internal));
            assert_eq!(received, Err(BrokerError::Internal));
        }
    }
    *platform.transferred.lock().unwrap() = Some(0);
    assert_eq!(
        send(&process, socket, &[0u8; 0], SendFlags::NONE),
        Ok(SocketOutcome::Completed(0))
    );
}
