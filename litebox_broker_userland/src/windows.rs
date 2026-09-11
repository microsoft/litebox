// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-userland broker launcher.

use std::error::Error;
use std::ffi::OsString;
use std::io::Result as IoResult;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::thread::JoinHandle;
use std::time::Instant;

use clap::Parser as _;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_platform_windows_userland::WindowsSyncPrimitivesProvider;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, WindowsNamedPipeStream,
    validate_client_process,
};
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;
use litebox_broker_userland::builder::BrokerCoreBuilder;

use super::{SETUP_TIMEOUT, configured_socket_policy};

pub(super) fn run(args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    let control_pipe = unique_control_pipe_name();
    let control_listener = WindowsNamedPipeListener::bind(&control_pipe)?;
    let policy = PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()).with_socket_policy(
        configured_socket_policy(&args.allow_tcp_destination, &args.allow_udp_destination)?,
    );
    let fs = super::fs::create_file_service::<WindowsSyncPrimitivesProvider>(
        args.fs_initial_files.as_deref(),
    )?;
    let broker = BrokerCoreBuilder::new(policy)
        .with_file_service(fs)
        .build()?;

    if args.in_process_runner {
        debug_assert!(args.unstable);
        run_runner_in_process(&args, &control_pipe, &broker, control_listener)
    } else {
        crate::run_runner_process(&args, &control_pipe, None, |runner, runner_process_id| {
            serve_runner_process(&broker, control_listener, runner, runner_process_id)?;
            Ok(())
        })
    }
}

fn run_runner_in_process(
    args: &super::CliArgs,
    control_pipe: &std::ffi::OsStr,
    broker: &BrokerCore,
    control_listener: WindowsNamedPipeListener,
) -> Result<(), Box<dyn Error>> {
    let runner_args = litebox_runner_windows_userland::CliArgs::try_parse_from(
        std::iter::once(OsString::from("litebox-runner-windows-userland"))
            .chain(crate::runner_command_arguments(args, control_pipe, None)),
    )?;
    let runner = std::thread::Builder::new()
        .name("litebox-runner".to_owned())
        .spawn(move || {
            litebox_runner_windows_userland::run(runner_args).map_err(|error| format!("{error:#}"))
        })?;
    let association_result = serve_runner_in_process(broker, control_listener, &runner);
    crate::finish_in_process_runner(runner, association_result)
}

fn serve_runner_process(
    broker: &BrokerCore,
    mut control_listener: WindowsNamedPipeListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> IoResult<()> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(
        setup_deadline,
        "control",
        || {
            runner
                .try_wait()
                .map(|status| status.map(|status| format!("exited with {status}")))
        },
        || control_listener.try_accept(),
    )?;
    validate_client_process(&control_stream, runner_process_id)?;
    let runner_process = runner.as_raw_handle();
    serve_control_stream(
        broker,
        control_stream,
        setup_deadline,
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, runner_process)?;
            channel.send_shared_memory(control_memory, runner_process)
        },
    )
}

fn serve_runner_in_process(
    broker: &BrokerCore,
    mut control_listener: WindowsNamedPipeListener,
    runner: &JoinHandle<super::InProcessRunnerResult>,
) -> IoResult<()> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(
        setup_deadline,
        "control",
        || Ok(runner.is_finished().then(|| "thread stopped".to_owned())),
        || control_listener.try_accept(),
    )?;
    validate_client_process(&control_stream, std::process::id())?;
    serve_control_stream(
        broker,
        control_stream,
        setup_deadline,
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory_to_current_process(shared_memory)?;
            channel.send_shared_memory_to_current_process(control_memory)
        },
    )
}

fn serve_control_stream(
    broker: &BrokerCore,
    control_stream: WindowsNamedPipeStream,
    setup_deadline: Instant,
    send_shared_memory: impl FnOnce(
        &mut WindowsNamedPipeHostSetupChannel,
        &WindowsSharedMemory,
        &WindowsSharedMemory,
    ) -> IoResult<()>,
) -> IoResult<()> {
    let control_channel =
        WindowsNamedPipeHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    litebox_broker_userland::runtime::serve_association(
        broker,
        control_channel,
        || WindowsSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        WindowsSharedMemory::create_control_ring,
        send_shared_memory,
        WindowsNamedPipeHostSetupChannel::into_active,
    )
}

fn unique_control_pipe_name() -> OsString {
    let process_id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(r"\\.\pipe\litebox-broker-{process_id}-{nonce}").into()
}
