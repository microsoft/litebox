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
//! owns shared memory but serves no objects beyond broker-managed process and thread state. Any
//! object request it receives is a bug in the test or in the shim and panics. The few tests that
//! genuinely exercise file-backed behavior (registry persistence and defaults, NLS section
//! mapping, file syscalls, and file-backed sections) use [`litebox_with_broker_files`].

extern crate std;

use alloc::{string::String, sync::Arc, vec::Vec};

use litebox_broker_core::{
    BrokerProcess, CallerCredential, ObjectRights, PolicyEngine,
    fs::{in_mem::InitialNode, resolver::Resolver},
    test_support::TestBrokerCoreBuilder,
};
use litebox_broker_host::test_support::{InProcessBrokerSetup, shared_memory};
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    BROKER_PROTOCOL_VERSION,
    message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerOperation, BrokerRequest,
        BrokerResponse,
    },
};
use litebox_broker_transport::{
    channel::{LocalCallChannel, LocalSetupChannel},
    shared_memory::SharedMemory,
};

use crate::tests::TestPlatform;

/// Returns a LiteBox whose broker association serves no objects.
///
/// The association negotiates the protocol and owns real shared memory, so the local side of the
/// boundary behaves normally, but object requests panic. Process and thread lifecycle operations are
/// handled by a real broker core.
pub(crate) fn litebox(
    platform: &'static TestPlatform,
) -> (
    litebox::LiteBox<TestPlatform>,
    litebox_broker_protocol::ProcessId,
) {
    let broker = crate::tests::objectless_broker();
    let channel = ObjectlessChannel {
        memory: shared_memory(),
        process: Some(
            broker
                .create_process(CallerCredential::Unauthenticated)
                .unwrap(),
        ),
    };
    let (broker_local, ()) = BrokerLocal::negotiate(channel, |channel| {
        let memory = Arc::clone(&channel.memory);
        Ok((channel, memory, ()))
    })
    .expect("the objectless broker fixture must negotiate");
    let process_id = broker_local.process_id();
    (
        litebox::LiteBox::new_with_broker_local(platform, broker_local),
        process_id,
    )
}

/// The local end of an association that owns shared memory but no objects.
struct ObjectlessChannel {
    memory: Arc<dyn SharedMemory>,
    process: Option<Arc<BrokerProcess>>,
}

impl ObjectlessChannel {
    fn process(&self) -> &BrokerProcess {
        self.process
            .as_deref()
            .expect("the objectless broker process must remain active")
    }
}

impl Drop for ObjectlessChannel {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            process.finish();
        }
    }
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
            process_id: self.process().id(),
        }))
    }
}

impl LocalCallChannel for ObjectlessChannel {
    type Error = core::convert::Infallible;

    fn call(&self, request: BrokerRequest) -> core::result::Result<BrokerResponse, Self::Error> {
        let result = match request.operation {
            BrokerOperation::CreateThread => self.process().create_thread().map_or_else(
                |error| litebox_broker_protocol::message::BrokerResult::Error(error.into()),
                litebox_broker_protocol::message::BrokerResult::ThreadCreated,
            ),
            BrokerOperation::ExitThread(thread_id) => {
                self.process().exit_thread(thread_id).map_or_else(
                    |error| litebox_broker_protocol::message::BrokerResult::Error(error.into()),
                    |()| litebox_broker_protocol::message::BrokerResult::ThreadExited,
                )
            }
            BrokerOperation::File(request) => panic!(
                "this task's broker serves no files; tests that need them must build their task \
                 with `crate::tests::test_task_with_broker_files`: {request:?}"
            ),
            operation => panic!("this task's broker serves no objects: {operation:?}"),
        };
        Ok(BrokerResponse {
            request_id: request.request_id,
            result,
        })
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
) -> (
    litebox::LiteBox<TestPlatform>,
    litebox_broker_protocol::ProcessId,
) {
    let in_mem = litebox_broker_core::fs::in_mem::InMem::<TestPlatform>::new_initialized(entries);
    let fs = litebox_broker_core::fs::composer::Composer::builder()
        .mount("/", |_| in_mem)
        .mount("/dev", litebox_broker_core::fs::devices::Devices::new)
        .build()
        .unwrap();
    let broker = TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .with_file_service(Arc::new(Resolver::<TestPlatform, _>::new(fs)))
    .build()
    .expect("a test process may build only one broker core");

    let setup = InProcessBrokerSetup::new(broker);
    let readiness = setup.readiness_sink();
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap();
    let process_id = broker_local.process_id();
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    readiness.attach(litebox.broker_notification_dispatcher());
    (litebox, process_id)
}
