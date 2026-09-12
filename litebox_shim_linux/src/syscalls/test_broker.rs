// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! In-process broker setup for the Linux shim's unit tests.
//!
//! The broker core and its mutable in-memory fs are process-wide. The repository's supported
//! `cargo nextest` runner isolates each test in its own process.

extern crate std;

use alloc::{sync::Arc, vec};
use std::sync::OnceLock;

use litebox_broker_core::{
    BrokerCore, BrokerCoreLimits, ObjectRights, PolicyEngine,
    fs::{in_mem::InitialNode, resolver::Resolver},
    random::{RandomProvider, RandomProviderError},
    socket::UnsupportedSocketProvider,
    stdio::{StdioProvider, StdioProviderError},
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    fs::{FileMode, FileUser},
    stdio::{StdioOutputStream, StdioStream},
};

use crate::syscalls::tests::TestPlatform;

const MAX_TEST_BROKER_REFERENCES: usize = 16;

/// Returns a LiteBox connected to the process-wide test broker.
pub(crate) fn litebox(platform: &'static TestPlatform) -> litebox::LiteBox<TestPlatform> {
    let setup = InProcessBrokerSetup::new(test_broker().clone());
    let readiness = setup.readiness_sink();
    let (broker_local, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
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
