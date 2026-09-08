// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

extern crate std;

use alloc::{boxed::Box, sync::Arc, vec};

use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::{backend::Backend, resolver::Resolver as CoreResolver},
    random::{RandomProvider, RandomProviderError},
    readiness::ReadinessSink,
    socket::UnsupportedSocketProvider,
    stdio::UnsupportedStdioProvider,
};
use litebox_broker_host::{BrokerHostAssociation, BrokerHostError};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    BROKER_PROTOCOL_VERSION, ObjectHandle,
    message::{BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse},
    readiness::ReadinessFlags,
    shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE},
};
use litebox_broker_transport::{
    channel::{HostReceive, HostSetupChannel, LocalCallChannel, LocalSetupChannel, PeerCredential},
    shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError},
};

use crate::platform::mock::MockPlatform;

pub(crate) fn brokered_fs<BackendType: Backend>(
    litebox: &crate::LiteBox<MockPlatform>,
    backend: BackendType,
) -> crate::fs::resolver::Resolver<MockPlatform> {
    static BROKER: std::sync::OnceLock<BrokerCore> = std::sync::OnceLock::new();
    let broker = BROKER.get_or_init(|| {
        BrokerCore::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all()),
            Arc::new(UnsupportedSocketProvider),
            Arc::new(UnusedRandomProvider),
            Arc::new(UnsupportedStdioProvider),
            Arc::new(CoreResolver::<MockPlatform, _>::new(backend)),
        )
        .unwrap()
    });

    let setup = TestBrokerSetup::new(broker);
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory: Arc<dyn SharedMemory> = setup.memory.clone();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap();
    let litebox = crate::LiteBox::new_with_broker_local(litebox.x.platform, broker_local);
    crate::fs::resolver::Resolver::new_brokered(&litebox)
}

struct TestBrokerSetup {
    broker: &'static BrokerCore,
    memory: Arc<TestSharedMemory>,
}

impl TestBrokerSetup {
    fn new(broker: &'static BrokerCore) -> Self {
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
            self.broker,
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

struct TestSharedMemory(std::sync::Mutex<alloc::vec::Vec<u8>>);

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

struct UnusedRandomProvider;

impl RandomProvider for UnusedRandomProvider {
    fn fill(&self, _output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        Err(RandomProviderError)
    }
}
