// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsString;
use std::io::Result as IoResult;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, validate_client_process,
};
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

use super::{ChildRunner, RunnerChildren, SETUP_TIMEOUT, accept_runner_channel};
use crate::runtime::{AssociationFailureCause, AssociationRunResult};

pub(super) struct PlatformRunnerShutdown {
    process_handle: isize,
}

impl PlatformRunnerShutdown {
    pub(super) fn new(runner: &Child) -> Self {
        Self {
            process_handle: runner.as_raw_handle() as isize,
        }
    }

    pub(super) fn shutdown(&self) -> bool {
        // SAFETY: the launch owner retains the `Child` and its process handle
        // until all shutdown callers finish and the runner has been waited.
        unsafe { TerminateProcess(self.process_handle as HANDLE, 1) != 0 }
    }

    pub(super) fn has_exited(&self) -> IoResult<bool> {
        // SAFETY: the launch owner retains the `Child` process handle until
        // shutdown is retired and the runner is waited.
        match unsafe { WaitForSingleObject(self.process_handle as HANDLE, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(std::io::Error::last_os_error()),
            _ => Err(std::io::Error::other(
                "waiting for the runner process returned an unknown status",
            )),
        }
    }
}

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
        runner: &Arc<Mutex<Child>>,
        children: Arc<RunnerChildren>,
    ) -> AssociationRunResult {
        serve_runner_process(
            self.listener
                .as_mut()
                .expect("a live runner instance must own its control listener"),
            runner,
            children,
        )
    }

    pub(super) fn serve_child(
        &mut self,
        runner: &Arc<Mutex<Child>>,
        child: ChildRunner,
        children: Arc<RunnerChildren>,
    ) -> AssociationRunResult {
        serve_child_runner_process(
            self.listener
                .as_mut()
                .expect("a live runner instance must own its control listener"),
            runner,
            child,
            children,
        )
    }

    pub(super) fn close(&mut self) {
        self.listener.take();
    }
}

fn serve_runner_process(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &Arc<Mutex<Child>>,
    children: Arc<RunnerChildren>,
) -> AssociationRunResult {
    let (control_channel, _setup_deadline) = match accept_control_channel(control_listener, runner)
    {
        Ok(connection) => connection,
        Err(error) => {
            let failure_cause = if non_reaping_runner_has_exited(runner).unwrap_or(false) {
                AssociationFailureCause::RunnerExit
            } else {
                AssociationFailureCause::Other
            };
            return AssociationRunResult {
                result: Err(error),
                process: None,
                panicked: false,
                abnormal: failure_cause == AssociationFailureCause::Other,
                failure_cause,
            };
        }
    };
    let runner_process = runner
        .lock()
        .expect("runner process mutex poisoned")
        .as_raw_handle();
    crate::runtime::serve_runner_association(
        None,
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

fn serve_child_runner_process(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &Arc<Mutex<Child>>,
    child: ChildRunner,
    children: Arc<RunnerChildren>,
) -> AssociationRunResult {
    let (control_channel, _setup_deadline) = match accept_control_channel(control_listener, runner)
    {
        Ok(connection) => connection,
        Err(error) => {
            let failure_cause = if non_reaping_runner_has_exited(runner).unwrap_or(false) {
                AssociationFailureCause::RunnerExit
            } else if matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) {
                AssociationFailureCause::PeerClosed
            } else {
                AssociationFailureCause::Other
            };
            return AssociationRunResult {
                result: Err(error),
                process: None,
                panicked: false,
                abnormal: failure_cause == AssociationFailureCause::Other,
                failure_cause,
            };
        }
    };
    let runner_process = runner
        .lock()
        .expect("runner process mutex poisoned")
        .as_raw_handle();
    let mut result = crate::runtime::serve_runner_association(
        Some(child),
        control_channel,
        || WindowsSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        WindowsSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, runner_process)?;
            channel.send_shared_memory(control_memory, runner_process)
        },
        WindowsNamedPipeHostSetupChannel::into_active,
        children,
    );
    if result.failure_cause == AssociationFailureCause::Other
        && result
            .result
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
        && non_reaping_runner_has_exited(runner).unwrap_or(false)
    {
        result.failure_cause = AssociationFailureCause::RunnerExit;
    }
    result
}

fn accept_control_channel(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &Arc<Mutex<Child>>,
) -> IoResult<(WindowsNamedPipeHostSetupChannel, Instant)> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = accept_runner_channel(
        setup_deadline,
        "control",
        || non_reaping_runner_has_exited(runner).map(|exited| exited.then(|| "exited".to_owned())),
        || control_listener.try_accept(),
    )?;
    let runner_id = runner.lock().expect("runner process mutex poisoned").id();
    validate_client_process(&control_stream, runner_id)?;
    Ok((
        WindowsNamedPipeHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline),
        setup_deadline,
    ))
}

fn non_reaping_runner_has_exited(runner: &Arc<Mutex<Child>>) -> IoResult<bool> {
    PlatformRunnerShutdown::new(&runner.lock().expect("runner process mutex poisoned")).has_exited()
}

fn unique_control_pipe_name() -> OsString {
    let process_id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(r"\\.\pipe\litebox-broker-{process_id}-{nonce}").into()
}
