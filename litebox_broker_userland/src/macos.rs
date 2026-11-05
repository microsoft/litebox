// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS-userland broker launcher.
//!
//! The macOS broker serves out-of-process runners with file, stdio, terminal,
//! timer, random, process-lifecycle, guest TCP and UDP networking, and, with
//! `--vsock-uds`, hybrid vsock services. The egress proxy (`--allow-host`) and
//! the in-process runner mode are not supported on macOS.
//!
//! The broker exits with its runner's exit code, so callers observe the guest's
//! exit status (`128 + signal` for a guest killed by a signal).

use std::error::Error;
use std::io::{Error as IoError, ErrorKind};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitCode;
use std::sync::Arc;

use litebox_broker_core::stdio::StdioProvider as _;
use litebox_broker_core::{ObjectRights, PolicyEngine};
use litebox_broker_platform_macos_userland::MacosSyncPrimitivesProvider;
use litebox_broker_protocol::vsock_socket::VsockCid;
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
        .with_process_duplication_enabled(args.allow_process_duplication)
        .with_vsock_policy(super::configured_vsock_policy(args.vsock_uds.is_some()));
    let terminal = stdio.terminal();
    let fs = super::create_file_service::<MacosSyncPrimitivesProvider>(
        args.fs_initial_files.as_deref(),
        &args.mounts,
        stdio,
    )?;
    let vsock_uds = args
        .vsock_uds
        .as_deref()
        .map(|path| (path, VsockCid(args.vsock_guest_cid)));
    // The bridge runs until `run` returns.
    let (broker, _vsock) = super::build_broker(policy, fs, terminal, vsock_uds)?;
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
