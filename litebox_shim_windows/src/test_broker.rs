// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker endpoints for the Windows shim's unit tests.
//!
//! The shim owns the guest side of the guest/broker boundary: NT syscall argument validation,
//! object and handle bookkeeping, path and flag translation, and error translation. Broker
//! authority — policy and filesystem semantics — belongs to `litebox_broker_core` and is tested
//! there.
//!
//! Ordinary shim tests therefore use [`litebox`], whose association has no file service. The few
//! tests that genuinely exercise file-backed behavior (registry persistence and defaults, NLS
//! section mapping, file syscalls, and file-backed sections) use [`litebox_with_broker_files`].

extern crate std;

use alloc::{string::String, sync::Arc, vec::Vec};

use litebox_broker_core::{
    BrokerCore, ObjectRights, PolicyEngine,
    fs::{in_mem::InitialNode, resolver::Resolver},
    test_support::TestBrokerCoreBuilder,
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;

use crate::tests::TestPlatform;

/// Returns a LiteBox whose broker association has no file service.
///
/// # Panics
///
/// Panics if a broker core already exists in this process. `cargo nextest`, the supported runner,
/// gives each test its own process.
pub(crate) fn litebox(platform: &'static TestPlatform) -> (litebox::LiteBox<TestPlatform>, usize) {
    connect(platform, test_broker())
}

fn test_broker() -> BrokerCore {
    TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .build()
    .expect("a test process may build only one broker core")
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
) -> (litebox::LiteBox<TestPlatform>, usize) {
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

    connect(platform, broker)
}

fn connect(
    platform: &'static TestPlatform,
    broker: BrokerCore,
) -> (litebox::LiteBox<TestPlatform>, usize) {
    let setup = InProcessBrokerSetup::new(broker);
    let readiness = setup.readiness_sink();
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((setup.activate(), memory, ()))
    })
    .unwrap();
    let process_id = broker_local.process_id().0 as usize;
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    readiness.attach(litebox.broker_notification_dispatcher());
    (litebox, process_id)
}
