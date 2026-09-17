// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsString;
use std::io::Result as IoResult;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::sync::Arc;
use std::time::Instant;

use litebox_broker_core::BrokerCore;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, validate_client_process,
};
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;

use super::{PreparedRunner, RunnerChildren, SETUP_TIMEOUT, accept_runner_channel};

pub(super) struct PlatformRunnerEndpoint {
    pipe_name: OsString,
    listener: Option<WindowsNamedPipeListener>,
}

impl PlatformRunnerEndpoint {
    pub(super) fn create() -> IoResult<Self> {
        let pipe_name = unique_control_pipe_name();
        let listener = WindowsNamedPipeListener::bind(&pipe_name)?;
        Ok(Self {
            pipe_name,
            listener: Some(listener),
        })
    }

    pub(super) fn control_channel(&self) -> &std::ffi::OsStr {
        &self.pipe_name
    }

    pub(super) fn serve(
        &mut self,
        broker: &BrokerCore,
        runner: &mut Child,
        children: Arc<RunnerChildren>,
    ) -> IoResult<()> {
        serve_runner_process(
            broker,
            self.listener
                .as_mut()
                .expect("a live runner instance must own its control listener"),
            runner,
            children,
        )
    }

    pub(super) fn serve_prepared(
        &mut self,
        runner: &mut Child,
        prepared: PreparedRunner,
        children: Arc<RunnerChildren>,
    ) -> IoResult<()> {
        serve_prepared_runner_process(
            self.listener
                .as_mut()
                .expect("a live runner instance must own its control listener"),
            runner,
            prepared,
            children,
        )
    }

    pub(super) fn close(&mut self) {
        self.listener.take();
    }
}

fn serve_runner_process(
    broker: &BrokerCore,
    control_listener: &mut WindowsNamedPipeListener,
    runner: &mut Child,
    children: Arc<RunnerChildren>,
) -> IoResult<()> {
    let (control_channel, _setup_deadline) = accept_control_channel(control_listener, runner)?;
    let runner_process = runner.as_raw_handle();
    crate::runtime::serve_runner_association(
        broker,
        control_channel,
        || WindowsSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        WindowsSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, runner_process)?;
            channel.send_shared_memory(control_memory, runner_process)
        },
        WindowsNamedPipeHostSetupChannel::into_active,
        children,
    )
}

fn serve_prepared_runner_process(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &mut Child,
    prepared: PreparedRunner,
    children: Arc<RunnerChildren>,
) -> IoResult<()> {
    let (control_channel, _setup_deadline) = accept_control_channel(control_listener, runner)?;
    let runner_process = runner.as_raw_handle();
    crate::runtime::serve_prepared_association(
        prepared,
        control_channel,
        || WindowsSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        WindowsSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, runner_process)?;
            channel.send_shared_memory(control_memory, runner_process)
        },
        WindowsNamedPipeHostSetupChannel::into_active,
        children,
    )
}

fn accept_control_channel(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &mut Child,
) -> IoResult<(WindowsNamedPipeHostSetupChannel, Instant)> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = accept_runner_channel(
        setup_deadline,
        "control",
        || {
            runner
                .try_wait()
                .map(|status| status.map(|status| format!("exited with {status}")))
        },
        || control_listener.try_accept(),
    )?;
    validate_client_process(&control_stream, runner.id())?;
    Ok((
        WindowsNamedPipeHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline),
        setup_deadline,
    ))
}

fn unique_control_pipe_name() -> OsString {
    let process_id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(r"\\.\pipe\litebox-broker-{process_id}-{nonce}").into()
}
