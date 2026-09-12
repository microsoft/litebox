// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker setup for the Linux shim's unit tests.
//!
//! The broker core and its mutable in-memory fs are process-wide. The repository's supported
//! `cargo nextest` runner isolates each test in its own process.

extern crate std;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use std::sync::{Mutex, OnceLock};

use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, ObjectRights, PolicyEngine,
    fs::{in_mem::InitialNode, resolver::Resolver},
    random::{RandomProvider, RandomProviderError},
    readiness::ReadinessSink,
    socket::UnsupportedSocketProvider,
    stdio::{StdioProvider, StdioProviderError},
};
use litebox_broker_host::{BrokerHostAssociation, BrokerHostError};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    BROKER_PROTOCOL_VERSION, ObjectHandle,
    fs::{FileMode, FileUser},
    message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
        BrokerResponse, ReadinessNotification,
    },
    readiness::ReadinessFlags,
    shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE},
    stdio::{StdioOutputStream, StdioStream},
};
use litebox_broker_transport::{
    channel::{HostReceive, HostSetupChannel, LocalCallChannel, LocalSetupChannel, PeerCredential},
    shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError},
};

use crate::syscalls::tests::TestPlatform;

const MAX_TEST_BROKER_REFERENCES: usize = 16;

/// Returns a LiteBox connected to the process-wide test broker.
pub(crate) fn litebox(platform: &'static TestPlatform) -> litebox::LiteBox<TestPlatform> {
    let readiness = Arc::new(TestReadinessSink::default());
    let setup = TestBrokerSetup::new(test_broker().clone(), Arc::clone(&readiness));
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory: Arc<dyn SharedMemory> = setup.memory.clone();
        Ok((setup.activate(), memory, ()))
    })
    .expect("the test broker must negotiate");
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    readiness.attach(litebox.broker_notification_dispatcher());
    litebox
}

fn test_broker() -> &'static BrokerCore {
    static BROKER: OnceLock<BrokerCore> = OnceLock::new();
    BROKER.get_or_init(|| {
        let root = InitialNode::Directory {
            mode: FileMode::RWXU | FileMode::RWXG | FileMode::RWXO,
            owner: FileUser::ROOT,
        };
        let in_mem =
            litebox_broker_core::fs::in_mem::InMem::<TestPlatform>::new_initialized(vec![(
                "/", root,
            )]);
        let fs = litebox_broker_core::fs::composer::Composer::builder()
            .mount("/", |_| in_mem)
            .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
            .build()
            .expect("the test filesystem must be valid");
        BrokerCore::new_with_limits(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            BrokerCoreLimits::new(
                MAX_TEST_BROKER_REFERENCES,
                BrokerCoreLimits::DEFAULT.max_total_pipe_capacity,
            ),
            Arc::new(UnsupportedSocketProvider),
            Arc::new(UnusedRandomProvider),
            Arc::new(TestStdioProvider),
            Arc::new(Resolver::<TestPlatform, _>::new(fs)),
        )
        .expect("a test process may build only one broker core")
    })
}

struct TestBrokerSetup {
    broker: BrokerCore,
    memory: Arc<TestSharedMemory>,
    readiness: Arc<TestReadinessSink>,
}

impl TestBrokerSetup {
    fn new(broker: BrokerCore, readiness: Arc<TestReadinessSink>) -> Self {
        Self {
            broker,
            memory: Arc::new(TestSharedMemory::new()),
            readiness,
        }
    }

    fn activate(self) -> TestBrokerChannel {
        let shared_buffers = Box::leak(Box::new(
            SharedBufferPool::new(self.memory, SHARED_BUFFER_LAYOUT)
                .expect("the test shared-buffer layout must be valid"),
        ));
        let mut setup = TestHostSetup;
        let association = litebox_broker_host::setup_connection(
            &self.broker,
            &mut setup,
            shared_buffers,
            self.readiness,
            |_| Ok(()),
        )
        .expect("the test broker setup must succeed")
        .expect("the test broker must accept the connection");
        TestBrokerChannel { association }
    }
}

impl LocalSetupChannel for TestBrokerSetup {
    type Error = BrokerHostError<core::convert::Infallible>;

    fn send_handshake_request(
        &mut self,
        request: &BrokerHandshakeRequest,
    ) -> core::result::Result<(), Self::Error> {
        assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
        Ok(())
    }

    fn recv_handshake_response(
        &mut self,
    ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
        Ok(Some(BrokerHandshakeResponse::Negotiated {
            broker_protocol_version: BROKER_PROTOCOL_VERSION,
        }))
    }
}

struct TestBrokerChannel {
    association: BrokerHostAssociation<'static, Arc<TestSharedMemory>>,
}

impl LocalCallChannel for TestBrokerChannel {
    type Error = BrokerHostError<core::convert::Infallible>;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        let mut response = None;
        self.association.execute_request(request, |value| {
            response = Some(value.clone());
            Ok(())
        })?;
        Ok(response.expect("the test broker must publish one response"))
    }
}

struct TestHostSetup;

impl HostSetupChannel for TestHostSetup {
    type Error = core::convert::Infallible;

    fn peer_credential(&self) -> core::result::Result<PeerCredential, Self::Error> {
        Ok(PeerCredential::Unauthenticated)
    }

    fn recv_handshake_request(
        &mut self,
    ) -> core::result::Result<HostReceive<BrokerHandshakeRequest>, Self::Error> {
        Ok(HostReceive::Message(BrokerHandshakeRequest {
            protocol_version: BROKER_PROTOCOL_VERSION,
        }))
    }

    fn send_handshake_response(
        &mut self,
        response: &BrokerHandshakeResponse,
    ) -> core::result::Result<(), Self::Error> {
        assert!(matches!(
            response,
            BrokerHandshakeResponse::Negotiated { .. }
        ));
        Ok(())
    }
}

type NotificationDispatcher = Box<dyn Fn(BrokerNotification) + Send>;

#[derive(Default)]
struct TestReadinessSink {
    dispatcher: Mutex<Option<NotificationDispatcher>>,
}

impl TestReadinessSink {
    fn attach(&self, dispatcher: impl Fn(BrokerNotification) + Send + 'static) {
        let previous = self
            .dispatcher
            .lock()
            .unwrap()
            .replace(Box::new(dispatcher));
        assert!(
            previous.is_none(),
            "the readiness sink must be attached once"
        );
    }

    fn dispatch(&self, handle: ObjectHandle, readiness: ReadinessFlags) {
        self.dispatcher
            .lock()
            .unwrap()
            .as_ref()
            .expect("the readiness sink must be attached before requests")(
            BrokerNotification::Readiness(ReadinessNotification { handle, readiness }),
        );
    }
}

impl ReadinessSink for TestReadinessSink {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(
        &self,
        handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        self.dispatch(handle, readiness);
        Ok(())
    }

    fn republish(
        &self,
        handle: ObjectHandle,
        readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        self.dispatch(handle, readiness);
        Ok(())
    }

    fn retire(&self, _handle: ObjectHandle) {}
}

struct UnusedRandomProvider;

impl RandomProvider for UnusedRandomProvider {
    fn fill(&self, _output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        Err(RandomProviderError)
    }
}

struct TestStdioProvider;

impl StdioProvider for TestStdioProvider {
    fn read(
        &self,
        _cancellation: &litebox_broker_core::AssociationCancellation,
        _output: &mut [u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        panic!("Linux shim unit tests must not read host standard input")
    }

    fn write(
        &self,
        _cancellation: &litebox_broker_core::AssociationCancellation,
        _stream: StdioOutputStream,
        _input: &[u8],
    ) -> core::result::Result<usize, StdioProviderError> {
        panic!("Linux shim unit tests must not write host standard output")
    }

    fn is_terminal(&self, stream: StdioStream) -> core::result::Result<bool, StdioProviderError> {
        Ok(stream == StdioStream::Stdout)
    }
}

/// Shared memory backed by an ordinary allocation, since no peer process observes it.
struct TestSharedMemory(Mutex<Vec<u8>>);

impl TestSharedMemory {
    fn new() -> Self {
        Self(Mutex::new(vec![0; SHARED_BUFFER_POOL_SIZE]))
    }
}

impl SharedMemory for TestSharedMemory {
    fn len(&self) -> usize {
        SHARED_BUFFER_POOL_SIZE
    }

    fn read(
        &self,
        offset: usize,
        destination: &mut [u8],
    ) -> core::result::Result<(), SharedMemoryError> {
        let memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(destination.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let source = memory
            .get(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> core::result::Result<(), SharedMemoryError> {
        let mut memory = self.0.lock().unwrap();
        let end = offset
            .checked_add(source.len())
            .ok_or(SharedMemoryError::InvalidRange)?;
        let destination = memory
            .get_mut(offset..end)
            .ok_or(SharedMemoryError::InvalidRange)?;
        destination.copy_from_slice(source);
        Ok(())
    }
}
