// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland broker launcher.
//!
//! The macOS broker serves out-of-process runners with file, stdio, timer,
//! random, and process-lifecycle services. Guest networking, host terminal
//! emulation, and the in-process runner mode are not supported on macOS.

use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;

use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_platform_macos_userland::MacosSyncPrimitivesProvider;
use litebox_broker_userland::builder::BrokerCoreBuilder;
use litebox_broker_userland::stdio::UserlandStdioProvider;

use super::configured_socket_policy;

pub(super) fn run(
    args: &super::CliArgs,
    stdio: Arc<UserlandStdioProvider>,
) -> Result<(), Box<dyn Error>> {
    if args.in_process_runner {
        return Err(IoError::new(
            ErrorKind::Unsupported,
            "--in-process-runner is not supported on macOS",
        )
        .into());
    }
    let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::all())
        .with_socket_policy(configured_socket_policy(
            &args.allow_tcp_destination,
            &args.allow_udp_destination,
        )?)
        .with_process_duplication_enabled(args.allow_process_duplication);
    let fs = super::create_file_service::<MacosSyncPrimitivesProvider>(
        args.fs_initial_files.as_deref(),
        &args.mounts,
        stdio,
    )?;
    let broker = BrokerCoreBuilder::new(policy)
        .with_file_service(fs)
        .build()?;
    crate::run_runner_instance(args, None, &broker)
}
