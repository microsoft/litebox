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

use super::{
    RunnerLauncher, RunnerStartup, SETUP_TIMEOUT, accept_runner_channel, runner_has_exited,
};
use crate::runtime::{AssociationOutcome, is_peer_closed_error};

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
        startup: Option<RunnerStartup>,
        launcher: Arc<RunnerLauncher>,
    ) -> AssociationOutcome {
        serve_association(
            self.listener
                .as_ref()
                .expect("a live runner instance must own its control listener"),
            runner,
            startup,
            launcher,
        )
    }

    pub(super) fn close(&mut self) {
        self.listener.take();
        self.directory.take();
    }
}

fn serve_association(
    control_listener: &UnixListener,
    runner: &Arc<Mutex<Child>>,
    startup: Option<RunnerStartup>,
    launcher: Arc<RunnerLauncher>,
) -> AssociationOutcome {
    let has_parent_startup = startup.is_some();
    let (control_channel, setup_deadline) = match accept_control_channel(control_listener, runner) {
        Ok(connection) => connection,
        Err(error) => {
            let abnormal = !(runner_has_exited(runner).unwrap_or(false)
                || has_parent_startup && is_peer_closed_error(&error));
            return AssociationOutcome {
                result: Err(error),
                process: None,
                panicked: false,
                abnormal,
            };
        }
    };
    crate::runtime::serve_out_of_process_runner_association(
        startup,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
        launcher,
    )
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
