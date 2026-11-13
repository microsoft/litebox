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
use core::convert::Infallible;

use litebox_broker_core::{
    CallerCredential, ObjectRights, PolicyEngine,
    fs::{in_mem::InitialNode, resolver::Resolver},
    random::{RandomProvider, RandomProviderError},
    stdio::{StdioProvider, UnsupportedStdioProvider},
    test_support::{FailingRandomProvider, TestBroker, TestBrokerBuilder},
};
use litebox_broker_host::{
    BrokerHostError,
    test_support::{InProcessBrokerChannel, InProcessBrokerSetup},
};
use litebox_broker_local::BrokerLocal;
use litebox_broker_transport::channel::LocalCallChannel;

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

fn test_broker() -> TestBroker {
    TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .build()
    .expect("a test process may build only one broker core")
}

/// Like [`litebox`], but the broker fills random requests with a fixed byte pattern.
///
/// # Panics
///
/// Panics if a broker core already exists in this process.
pub(crate) fn litebox_with_random(
    platform: &'static TestPlatform,
) -> (litebox::LiteBox<TestPlatform>, usize) {
    let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .with_random_provider(Arc::new(FixedRandomProvider))
    .build()
    .expect("a test process may build only one broker core");
    connect(platform, broker)
}

/// Deterministic random source for tests that need broker randomness to succeed.
struct FixedRandomProvider;

impl RandomProvider for FixedRandomProvider {
    fn fill(&self, output: &mut [u8]) -> core::result::Result<(), RandomProviderError> {
        output.fill(0x5a);
        Ok(())
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
) -> (litebox::LiteBox<TestPlatform>, usize) {
    litebox_with_broker_files_and_stdio(platform, entries, Arc::new(UnsupportedStdioProvider))
}

/// Like [`litebox_with_broker_files`], but the broker's `/dev` standard-I/O devices use `stdio`.
pub(crate) fn litebox_with_broker_files_and_stdio(
    platform: &'static TestPlatform,
    entries: Vec<(String, InitialNode)>,
    stdio: Arc<dyn StdioProvider>,
) -> (litebox::LiteBox<TestPlatform>, usize) {
    let fs = litebox_broker_core::fs::composer::Composer::builder()
        .mount("/", |allocator| {
            litebox_broker_core::fs::in_mem::InMem::<TestPlatform>::new_initialized(
                entries, allocator,
            )
        })
        .mount("/dev", |allocator| {
            litebox_broker_core::fs::devices::Devices::new(
                allocator,
                stdio,
                Arc::new(FailingRandomProvider),
            )
        })
        .build()
        .unwrap();
    let broker = TestBrokerBuilder::new(PolicyEngine::with_unauthenticated_rights(
        ObjectRights::all(),
    ))
    .with_file_service(Arc::new(Resolver::<TestPlatform>::new(fs)))
    .build()
    .expect("a test process may build only one broker core");

    connect(platform, broker)
}

fn connect(
    platform: &'static TestPlatform,
    broker: TestBroker,
) -> (litebox::LiteBox<TestPlatform>, usize) {
    connect_with_channel(platform, broker, |channel| channel)
}

/// Like [`litebox`], but broker calls go through the channel `wrap_channel` builds around the
/// in-process one.
///
/// # Panics
///
/// Panics if a broker core already exists in this process.
pub(super) fn litebox_with_channel<Channel>(
    platform: &'static TestPlatform,
    wrap_channel: impl FnOnce(InProcessBrokerChannel) -> Channel,
) -> (litebox::LiteBox<TestPlatform>, usize)
where
    Channel: LocalCallChannel<Error = BrokerHostError<Infallible>> + Send + Sync + 'static,
{
    connect_with_channel(platform, test_broker(), wrap_channel)
}

fn connect_with_channel<Channel>(
    platform: &'static TestPlatform,
    broker: TestBroker,
    wrap_channel: impl FnOnce(InProcessBrokerChannel) -> Channel,
) -> (litebox::LiteBox<TestPlatform>, usize)
where
    Channel: LocalCallChannel<Error = BrokerHostError<Infallible>> + Send + Sync + 'static,
{
    let root = broker
        .create_process(CallerCredential::Unauthenticated)
        .expect("the test broker must create a root process");
    let setup = InProcessBrokerSetup::new(root);
    let readiness = setup.readiness_sink();
    let (broker_local, _startup, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((wrap_channel(setup.activate()), memory, ()))
    })
    .unwrap();
    let process_id = broker_local.process_id().0 as usize;
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    readiness.attach(litebox.broker_notification_dispatcher());
    (litebox, process_id)
}
