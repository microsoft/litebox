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
    test_support::{TerminalOnlyStdioProvider, TestBrokerCoreBuilder},
};
use litebox_broker_host::test_support::InProcessBrokerSetup;
use litebox_broker_local::BrokerLocal;
use litebox_broker_protocol::{
    fs::{FileMode, FileUser},
    stdio::StdioStream,
};

use crate::syscalls::tests::TestPlatform;

pub(crate) const MAX_TEST_BROKER_REFERENCES: usize = 16;

/// Returns a LiteBox connected to the process-wide test broker.
pub(crate) fn litebox(platform: &'static TestPlatform) -> (litebox::LiteBox<TestPlatform>, i32) {
    litebox_with_limits(
        platform,
        BrokerCoreLimits::new(
            MAX_TEST_BROKER_REFERENCES,
            BrokerCoreLimits::DEFAULT.max_total_pipe_capacity,
        ),
    )
}

/// Returns a LiteBox connected to the process-wide test broker with explicit limits.
pub(crate) fn litebox_with_limits(
    platform: &'static TestPlatform,
    limits: BrokerCoreLimits,
) -> (litebox::LiteBox<TestPlatform>, i32) {
    let setup = InProcessBrokerSetup::new(test_broker(limits).clone());
    let readiness = setup.readiness_sink();
    let (broker_local, _startup, ()) = BrokerLocal::negotiate(setup, |setup| {
        let memory = setup.shared_memory();
        Ok((setup.activate(), memory, ()))
    })
    .expect("the test broker must negotiate");
    let process_id =
        i32::try_from(broker_local.process_id().0).expect("process ID must fit Linux pid_t");
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    readiness.attach(litebox.broker_notification_dispatcher());
    (litebox, process_id)
}

fn test_broker(limits: BrokerCoreLimits) -> &'static BrokerCore {
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
        TestBrokerCoreBuilder::new(PolicyEngine::with_unauthenticated_rights(
            ObjectRights::all(),
        ))
        .with_limits(limits)
        .with_stdio_provider(Arc::new(
            TerminalOnlyStdioProvider::default().with_terminal(StdioStream::Stdout),
        ))
        .with_file_service(Arc::new(Resolver::<TestPlatform, _>::new(fs)))
        .build()
        .expect("a test process may build only one broker core")
    })
}
