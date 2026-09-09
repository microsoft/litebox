// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker endpoints for the Windows shim's unit tests.
//!
//! The shim owns the guest side of the guest/broker boundary: NT syscall argument validation,
//! object and handle bookkeeping, path and flag translation, and error translation. Broker
//! authority — policy and filesystem semantics — belongs to `litebox_broker_core` and is tested
//! there.
//!
//! Ordinary shim tests therefore use [`litebox`], whose association negotiates the protocol and
//! owns shared memory but serves no objects: any request it receives is a bug in the test or in
//! the shim, and panics. The few tests that genuinely exercise file-backed behavior (registry
//! persistence and defaults, NLS section mapping, file syscalls, and file-backed sections) use
//! [`litebox_with_broker_files`], which owns a broker core for the test process.

extern crate std;

use alloc::{boxed::Box, string::String, sync::Arc, vec, vec::Vec};

use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::{in_mem::InitialNode, resolver::Resolver},
    random::{RandomProvider, RandomProviderError},
    readiness::ReadinessSink,
    socket::UnsupportedSocketProvider,
    stdio::UnsupportedStdioProvider,
};
use litebox_broker_host::{BrokerHostAssociation, BrokerHostError};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    BROKER_PROTOCOL_VERSION, ObjectHandle,
    message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
        BrokerResponse,
    },
    readiness::ReadinessFlags,
    shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE},
};
use litebox_broker_transport::{
    channel::{HostReceive, HostSetupChannel, LocalCallChannel, LocalSetupChannel, PeerCredential},
    shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError},
};

use crate::tests::TestPlatform;

/// Returns a LiteBox whose broker association serves no objects.
///
/// The association negotiates the protocol and owns real shared memory, so the local side of the
/// boundary behaves normally, but every request panics. This keeps tests that are not about
/// broker-backed resources honest about what they exercise.
pub(crate) fn litebox(platform: &'static TestPlatform) -> litebox::LiteBox<TestPlatform> {
    let channel = ObjectlessChannel {
        memory: Arc::new(TestSharedMemory::new()),
    };
    let (broker_local, ()) = BrokerLocal::negotiate(channel, |channel| {
        let memory: Arc<dyn SharedMemory> = channel.memory.clone();
        Ok((channel, memory, ()))
    })
    .expect("the objectless broker fixture must negotiate");
    litebox::LiteBox::new_with_broker_local(platform, broker_local)
}

/// The local end of an association that owns shared memory but no objects.
struct ObjectlessChannel {
    memory: Arc<TestSharedMemory>,
}

impl LocalSetupChannel for ObjectlessChannel {
    type Error = core::convert::Infallible;

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

impl LocalCallChannel for ObjectlessChannel {
    type Error = core::convert::Infallible;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        match request.operation {
            BrokerOperation::File(request) => panic!(
                "this task's broker serves no files; tests that need them must build their task \
                 with `crate::tests::test_task_with_broker_files`: {request:?}"
            ),
            operation => panic!("this task's broker serves no objects: {operation:?}"),
        }
    }
}

/// Returns a LiteBox associated with a broker core that serves `entries` from memory.
///
/// # Panics
///
/// Panics if a broker core already exists in this process. The broker core is a process
/// singleton, so at most one file-backed task may be built per test binary invocation;
/// `cargo nextest`, the supported runner, gives each test its own process.
pub(crate) fn litebox_with_broker_files(
    platform: &'static TestPlatform,
    entries: Vec<(String, InitialNode)>,
) -> litebox::LiteBox<TestPlatform> {
    let in_mem = litebox_broker_core::fs::in_mem::InMem::<TestPlatform>::new_initialized(entries);
    let fs = litebox_broker_core::fs::composer::Composer::builder()
        .mount("/", |_| in_mem)
        .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
        .build()
        .unwrap();
    let broker = BrokerCore::new(
        PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
        Arc::new(UnsupportedSocketProvider),
        Arc::new(UnusedRandomProvider),
        Arc::new(UnsupportedStdioProvider),
        Arc::new(Resolver::<TestPlatform, _>::new(fs)),
    )
    .expect("a test process may build only one broker core");

    let setup = TestBrokerSetup::new(broker);
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory: Arc<dyn SharedMemory> = setup.memory.clone();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap();
    litebox::LiteBox::new_with_broker_local(platform, broker_local)
}

struct TestBrokerSetup {
    broker: BrokerCore,
    memory: Arc<TestSharedMemory>,
}

impl TestBrokerSetup {
    fn new(broker: BrokerCore) -> Self {
        Self {
            broker,
            memory: Arc::new(TestSharedMemory::new()),
        }
    }

    fn activate(self) -> TestBrokerChannel {
        let shared_buffers = Box::leak(Box::new(
            SharedBufferPool::new(self.memory, SHARED_BUFFER_LAYOUT).unwrap(),
        ));
        let mut setup = TestHostSetup;
        let association = litebox_broker_host::setup_connection(
            &self.broker,
            &mut setup,
            shared_buffers,
            Arc::new(TestReadinessSink),
            |_| Ok(()),
        )
        .unwrap()
        .unwrap();
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
        Ok(response.expect("broker host must publish one response"))
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

struct TestReadinessSink;

impl ReadinessSink for TestReadinessSink {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(
        &self,
        _handle: ObjectHandle,
        _readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
        Ok(())
    }

    fn republish(
        &self,
        _handle: ObjectHandle,
        _readiness: ReadinessFlags,
    ) -> litebox_broker_core::Result<()> {
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

/// Shared memory backed by an ordinary allocation, since no peer process observes it.
struct TestSharedMemory(std::sync::Mutex<Vec<u8>>);

impl TestSharedMemory {
    fn new() -> Self {
        Self(std::sync::Mutex::new(vec![0; SHARED_BUFFER_POOL_SIZE]))
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
