// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker association support for tests.

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, Ordering};

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
        InProcessBrokerChannel {
            association: Some(association),
            panicked: AtomicBool::new(false),
        }
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
            None,
            None,
            &mut host_setup,
            shared_buffers,
            readiness,
            |_| false,
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
    association: Option<BrokerHostAssociation<'static, Arc<InProcessSharedMemory>>>,
    panicked: AtomicBool,
}

impl LocalCallChannel for InProcessBrokerChannel {
    type Error = BrokerHostError<Infallible>;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        let mut guard = InProcessCallGuard {
            panicked: &self.panicked,
            completed: false,
        };
        let mut response = None;
        let result = self
            .association
            .as_ref()
            .expect("the in-process broker association must remain active")
            .execute_request(request, |value| {
                response = Some(value.clone());
                Ok(())
            })
            .map(|()| response.expect("the in-process broker must publish one response"));
        guard.completed = true;
        result
    }
}

impl Drop for InProcessBrokerChannel {
    fn drop(&mut self) {
        let association = self
            .association
            .take()
            .expect("the in-process broker association must be finished once");
        if self.panicked.load(Ordering::Acquire) {
            drop(association);
        } else {
            association.finish();
        }
    }
}

struct InProcessCallGuard<'a> {
    panicked: &'a AtomicBool,
    completed: bool,
}

impl Drop for InProcessCallGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.panicked.store(true, Ordering::Release);
        }
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
    use litebox_broker_core::{
        BrokerCoreLimits, ObjectRights, PolicyEngine, test_support::TestBrokerCoreBuilder,
    };
    use litebox_broker_protocol::{
        RequestId,
        message::{BrokerOperation, BrokerRequest, BrokerResult},
    };
    use litebox_broker_transport::channel::{LocalCallChannel, LocalSetupChannel};

    use super::*;

    #[test]
    fn dropping_active_channel_releases_remaining_thread_quota() {
        let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(BrokerCoreLimits::DEFAULT.with_thread_quotas(1, 1))
        .build()
        .unwrap();

        let first = active_channel(broker.clone());
        assert!(matches!(
            first
                .call(BrokerRequest {
                    request_id: RequestId(0),
                    operation: BrokerOperation::CreateThread,
                })
                .unwrap()
                .result,
            BrokerResult::ThreadCreated(_)
        ));
        drop(first);

        let second = active_channel(broker);
        assert!(matches!(
            second
                .call(BrokerRequest {
                    request_id: RequestId(0),
                    operation: BrokerOperation::CreateThread,
                })
                .unwrap()
                .result,
            BrokerResult::ThreadCreated(_)
        ));
    }

    fn active_channel(broker: litebox_broker_core::BrokerCore) -> InProcessBrokerChannel {
        let mut setup = InProcessBrokerSetup::new(broker);
        setup
            .send_handshake_request(&BrokerHandshakeRequest {
                protocol_version: BROKER_PROTOCOL_VERSION,
            })
            .unwrap();
        assert!(matches!(
            setup.recv_handshake_response().unwrap().unwrap(),
            BrokerHandshakeResponse::Negotiated { .. }
        ));
        setup.activate()
    }
}
