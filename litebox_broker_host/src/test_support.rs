// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker association support for tests.

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::convert::Infallible;

use litebox_broker_core::{BrokerCore, readiness::ReadinessSink};
use litebox_broker_protocol::{
    BROKER_PROTOCOL_VERSION, ObjectHandle,
    message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerNotification, BrokerRequest,
        BrokerResponse, ReadinessNotification,
    },
    readiness::ReadinessFlags,
    shared_buffer::{SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE},
};
use litebox_broker_transport::{
    channel::{HostReceive, HostSetupChannel, LocalCallChannel, LocalSetupChannel, PeerCredential},
    shared_memory::{SharedBufferPool, SharedMemory, SharedMemoryError},
};
use spin::mutex::SpinMutex;

use crate::{BrokerHostAssociation, BrokerHostError};

/// Local setup endpoint for an in-process broker association.
pub struct InProcessBrokerSetup {
    broker: BrokerCore,
    memory: Arc<InProcessSharedMemory>,
    readiness: Arc<InProcessReadinessSink>,
    association: Option<BrokerHostAssociation<'static, Arc<InProcessSharedMemory>>>,
}

impl InProcessBrokerSetup {
    /// Creates an in-process association backed by allocation-based shared memory.
    pub fn new(broker: BrokerCore) -> Self {
        Self {
            broker,
            memory: Arc::new(InProcessSharedMemory::new()),
            readiness: Arc::new(InProcessReadinessSink::default()),
            association: None,
        }
    }

    /// Returns the shared memory used by both association endpoints.
    pub fn shared_memory(&self) -> Arc<dyn SharedMemory> {
        self.memory.clone()
    }

    /// Returns the sink that forwards broker readiness to the local endpoint.
    pub fn readiness_sink(&self) -> Arc<InProcessReadinessSink> {
        Arc::clone(&self.readiness)
    }

    /// Activates the host association after local protocol negotiation.
    ///
    /// # Panics
    ///
    /// Panics if the fixed test shared-memory layout is invalid or the canned
    /// unauthenticated host setup cannot establish the association.
    pub fn activate(mut self) -> InProcessBrokerChannel {
        let association = self
            .association
            .take()
            .expect("the in-process local endpoint must negotiate before activation");
        InProcessBrokerChannel { association }
    }
}

impl LocalSetupChannel for InProcessBrokerSetup {
    type Error = BrokerHostError<Infallible>;

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
        assert!(
            self.association.is_none(),
            "the in-process broker association must be negotiated only once"
        );
        let shared_buffers = Box::leak(Box::new(
            SharedBufferPool::new(Arc::clone(&self.memory), SHARED_BUFFER_LAYOUT)
                .expect("the in-process shared-buffer layout must be valid"),
        ));
        let mut host_setup = InProcessHostSetup { response: None };
        let readiness: Arc<dyn ReadinessSink> = self.readiness.clone();
        let association = crate::setup_connection(
            &self.broker,
            &mut host_setup,
            shared_buffers,
            readiness,
            |_| Ok(()),
        )
        .expect("the in-process broker setup must succeed")
        .expect("the in-process broker must accept the connection");
        self.association = Some(association);
        Ok(Some(host_setup.response.expect(
            "the in-process broker must send a handshake response",
        )))
    }
}

/// Active request channel for an in-process broker association.
pub struct InProcessBrokerChannel {
    association: BrokerHostAssociation<'static, Arc<InProcessSharedMemory>>,
}

impl LocalCallChannel for InProcessBrokerChannel {
    type Error = BrokerHostError<Infallible>;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        let mut response = None;
        self.association.execute_request(request, |value| {
            response = Some(value.clone());
            Ok(())
        })?;
        Ok(response.expect("the in-process broker must publish one response"))
    }
}

struct InProcessHostSetup {
    response: Option<BrokerHandshakeResponse>,
}

impl HostSetupChannel for InProcessHostSetup {
    type Error = Infallible;

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
        self.response = Some(response.clone());
        Ok(())
    }
}

type NotificationDispatcher = Box<dyn Fn(BrokerNotification) + Send>;

/// Readiness sink that forwards notifications to an attached local dispatcher.
#[derive(Default)]
pub struct InProcessReadinessSink {
    dispatcher: SpinMutex<Option<NotificationDispatcher>>,
}

impl InProcessReadinessSink {
    /// Attaches the local notification dispatcher.
    ///
    /// # Panics
    ///
    /// Panics if a dispatcher was already attached.
    pub fn attach(&self, dispatcher: impl Fn(BrokerNotification) + Send + 'static) {
        let previous = self.dispatcher.lock().replace(Box::new(dispatcher));
        assert!(
            previous.is_none(),
            "the in-process readiness sink must be attached once"
        );
    }

    fn dispatch(&self, handle: ObjectHandle, readiness: ReadinessFlags) {
        self.dispatcher
            .lock()
            .as_ref()
            .expect("the readiness sink must be attached before requests")(
            BrokerNotification::Readiness(ReadinessNotification { handle, readiness }),
        );
    }
}

impl ReadinessSink for InProcessReadinessSink {
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

/// Creates shared memory backed by an ordinary allocation.
pub fn shared_memory() -> Arc<dyn SharedMemory> {
    Arc::new(InProcessSharedMemory::new())
}

struct InProcessSharedMemory(SpinMutex<Vec<u8>>);

impl InProcessSharedMemory {
    fn new() -> Self {
        Self(SpinMutex::new(vec![0; SHARED_BUFFER_POOL_SIZE]))
    }
}

impl SharedMemory for InProcessSharedMemory {
    fn len(&self) -> usize {
        SHARED_BUFFER_POOL_SIZE
    }

    fn read(
        &self,
        offset: usize,
        destination: &mut [u8],
    ) -> core::result::Result<(), SharedMemoryError> {
        let memory = self.0.lock();
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
        let mut memory = self.0.lock();
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

#[cfg(test)]
mod tests {
    use litebox_broker_core::test_support::TestBrokerCoreBuilder;
    use litebox_broker_core::{CallerCredential, ObjectRights, PolicyEngine};
    use litebox_broker_transport::channel::LocalSetupChannel;

    use super::InProcessBrokerSetup;
    use litebox_broker_protocol::{
        BROKER_PROTOCOL_VERSION,
        message::{BrokerHandshakeRequest, BrokerHandshakeResponse},
    };

    #[test]
    fn handshake_returns_the_identity_allocated_by_the_host_session() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .build()
        .unwrap();
        let process = broker
            .create_process(CallerCredential::Unauthenticated)
            .unwrap();
        litebox_broker_core::BrokerProcess::finish(process);
        let mut setup = InProcessBrokerSetup::new(broker);

        setup
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        let response = setup.recv_handshake_response().unwrap().unwrap();

        let BrokerHandshakeResponse::Negotiated { process_id, .. } = response else {
            panic!("the in-process broker must negotiate");
        };
        assert_eq!(process_id.0, 2);
    }
}
