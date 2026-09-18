// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsStr;
use std::io::Result as IoResult;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{ChildRunner, RunnerChildren, SETUP_TIMEOUT, accept_runner_channel, runner_has_exited};
use crate::runtime::{AssociationFailureCause, AssociationRunResult};

pub(super) struct PlatformRunnerEndpoint {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
    directory: Option<tempfile::TempDir>,
}

impl PlatformRunnerEndpoint {
    pub(super) fn create() -> IoResult<Self> {
        let directory = tempfile::Builder::new()
            .prefix("litebox-broker-userland-")
            .tempdir()?;
        let socket_path = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            socket_path,
            listener: Some(listener),
            directory: Some(directory),
        })
    }

    pub(super) fn control_channel(&self) -> &OsStr {
        self.socket_path.as_os_str()
    }

    pub(super) fn serve(
        &mut self,
        runner: &Arc<Mutex<Child>>,
        children: Arc<RunnerChildren>,
    ) -> AssociationRunResult {
        serve_runner_process(
            self.listener
                .as_ref()
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
                .as_ref()
                .expect("a live runner instance must own its control listener"),
            runner,
            child,
            children,
        )
    }

    pub(super) fn close(&mut self) {
        self.listener.take();
        self.directory.take();
    }
}

fn serve_runner_process(
    control_listener: &UnixListener,
    runner: &Arc<Mutex<Child>>,
    children: Arc<RunnerChildren>,
) -> AssociationRunResult {
    let (control_channel, setup_deadline) = match accept_control_channel(control_listener, runner) {
        Ok(connection) => connection,
        Err(error) => {
            let failure_cause = if runner_has_exited(runner).unwrap_or(false) {
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
    crate::runtime::serve_runner_association(
        None,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
        children,
    )
}

fn serve_child_runner_process(
    control_listener: &UnixListener,
    runner: &Arc<Mutex<Child>>,
    child: ChildRunner,
    children: Arc<RunnerChildren>,
) -> AssociationRunResult {
    let (control_channel, setup_deadline) = match accept_control_channel(control_listener, runner) {
        Ok(connection) => connection,
        Err(error) => {
            let failure_cause = if runner_has_exited(runner).unwrap_or(false) {
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
    let mut result = crate::runtime::serve_runner_association(
        Some(child),
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
        children,
    );
    if result.failure_cause == AssociationFailureCause::Other
        && result
            .result
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
        && runner_has_exited(runner).unwrap_or(false)
    {
        result.failure_cause = AssociationFailureCause::RunnerExit;
    }
    result
}

fn accept_control_channel(
    control_listener: &UnixListener,
    runner: &Arc<Mutex<Child>>,
) -> IoResult<(UnixStreamHostSetupChannel, Instant)> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let runner_id = runner.lock().expect("runner process mutex poisoned").id();
    let control_stream = accept_runner_channel(
        setup_deadline,
        "control",
        || runner_has_exited(runner).map(|exited| exited.then(|| "exited".to_owned())),
        || control_listener.accept().map(|(stream, _)| stream),
    )?;
    validate_peer_process(&control_stream, runner_id)?;
    Ok((
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline),
        setup_deadline,
    ))
}
