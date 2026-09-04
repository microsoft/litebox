// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows-userland broker launcher.

use std::error::Error;
use std::ffi::OsString;
use std::io::Result as IoResult;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::sync::Arc;
use std::time::Instant;

use litebox_broker_core::socket::UnsupportedSocketProvider;
use litebox_broker_core::{BrokerCore, ObjectRights, PolicyEngine};
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::channel::HostReceive;
use litebox_broker_transport_windows_userland::control_ring::{
    WindowsControlRingHostRequestSource, WindowsControlRingHostResponseSink,
    WindowsControlRingHostShutdown,
};
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, validate_client_process,
};
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;

use super::{
    HostAssociationShutdown, HostRequestSource, HostResponseSink, SETUP_TIMEOUT,
    configured_socket_policy,
};
use super::{random::UserlandRandomProvider, stdio::UserlandStdioProvider};

impl HostRequestSource for WindowsControlRingHostRequestSource {
    fn recv_request(&mut self) -> IoResult<HostReceive<BrokerRequest>> {
        Self::recv_request(self)
    }
}

impl HostResponseSink for WindowsControlRingHostResponseSink {
    fn send_response(&self, response: &BrokerResponse) -> IoResult<()> {
        Self::send_response(self, response)
    }
}

impl HostAssociationShutdown for WindowsControlRingHostShutdown {
    fn shutdown(&self) -> IoResult<()> {
        Self::shutdown(self)
    }
}

pub(super) fn run(args: super::CliArgs) -> Result<(), Box<dyn Error>> {
    let control_pipe = unique_control_pipe_name();
    let control_listener = WindowsNamedPipeListener::bind(&control_pipe)?;
    let broker = BrokerCore::new(
        PolicyEngine::with_host_guaranteed_rights(ObjectRights::all()).with_socket_policy(
            configured_socket_policy(&args.allow_tcp_destination, &args.allow_udp_destination)?,
        ),
        Arc::new(UnsupportedSocketProvider),
        Arc::new(UserlandRandomProvider),
        Arc::new(UserlandStdioProvider::new(super::WORKER_COUNT)?),
    )?;

    crate::run_runner_process(&args, &control_pipe, None, |runner, runner_process_id| {
        serve_runner(&broker, control_listener, runner, runner_process_id)
    })
}

fn serve_runner(
    broker: &BrokerCore,
    mut control_listener: WindowsNamedPipeListener,
    runner: &mut Child,
    runner_process_id: u32,
) -> Result<(), Box<dyn Error>> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = crate::accept_runner_channel(runner, setup_deadline, "control", || {
        control_listener.try_accept()
    })?;
    validate_client_process(&control_stream, runner_process_id)?;
    let control_channel =
        WindowsNamedPipeHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    let runner_process = runner.as_raw_handle();
    crate::serve_runner(
        broker,
        control_channel,
        || WindowsSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        WindowsSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, runner_process)?;
            channel.send_shared_memory(control_memory, runner_process)
        },
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
