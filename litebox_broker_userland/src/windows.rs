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
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

use super::{
    HostAssociationShutdown, HostRequestSource, HostResponseSink, SETUP_TIMEOUT,
    configured_socket_policy,
};

pub(super) struct RunnerJob(HANDLE);

impl RunnerJob {
    pub(super) fn assign(runner: &Child) -> IoResult<Self> {
        // SAFETY: Null attributes and name request a new unnamed job object.
        let handle = unsafe { CreateJobObjectW(core::ptr::null(), core::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Self(handle);

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `job` owns a valid handle, and `limits` is initialized for
        // the information class and remains alive for the duration of the call.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                core::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }

        // SAFETY: Both handles are valid for this call. The job retains the
        // process association independently of the borrowed `Child`.
        if unsafe { AssignProcessToJobObject(job.0, runner.as_raw_handle()) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }
}

impl Drop for RunnerJob {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the owned handle returned by `CreateJobObjectW`.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

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
        Arc::new(super::UserlandRandomProvider),
        Arc::new(super::UserlandStdioProvider),
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
