// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland broker launcher.
//!
//! The macOS broker serves out-of-process runners with file, stdio, timer,
//! random, and process-lifecycle services. Guest networking, host terminal
//! emulation, and the in-process runner mode are not supported on macOS.
//!
//! The broker exits with its runner's exit code, so callers observe the guest's
//! exit status (`128 + signal` for a guest killed by a signal).

use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitCode;
use std::sync::Arc;

use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_platform_macos_userland::MacosSyncPrimitivesProvider;
use litebox_broker_userland::builder::BrokerCoreBuilder;
use litebox_broker_userland::stdio::UserlandStdioProvider;

use super::configured_socket_policy;

pub(super) fn run(
    args: &super::CliArgs,
    stdio: Arc<UserlandStdioProvider>,
) -> Result<ExitCode, Box<dyn Error>> {
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
    let status = crate::run_runner(args, None, &broker)?;
    // A runner reports a guest killed by a signal as `128 + signal`, so a host signal means the
    // runner itself died; report it the way a shell does.
    let code = status.code().unwrap_or_else(|| {
        let signal = status.signal().unwrap_or_default();
        eprintln!("runner terminated by signal {signal}");
        128 + signal
    });
    // macOS exit codes are 8-bit, so only an impossible value falls back to a failure.
    Ok(u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from))
}
