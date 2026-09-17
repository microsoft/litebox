// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::ffi::OsStr;
use std::io::Result as IoResult;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Child;
use std::time::Instant;

use litebox_broker_core::BrokerCore;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_linux_userland::memfd::MemfdSharedMemory;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{SETUP_TIMEOUT, accept_runner_channel};

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

    pub(super) fn serve(&mut self, broker: &BrokerCore, runner: &mut Child) -> IoResult<()> {
        serve_runner_process(
            broker,
            self.listener
                .as_ref()
                .expect("a live runner instance must own its control listener"),
            runner,
        )
    }

    pub(super) fn close(&mut self) {
        self.listener.take();
        self.directory.take();
    }
}

fn serve_runner_process(
    broker: &BrokerCore,
    control_listener: &UnixListener,
    runner: &mut Child,
) -> IoResult<()> {
    let setup_deadline = Instant::now() + SETUP_TIMEOUT;
    let control_stream = accept_runner_channel(
        setup_deadline,
        "control",
        || {
            runner
                .try_wait()
                .map(|status| status.map(|status| format!("exited with {status}")))
        },
        || control_listener.accept().map(|(stream, _)| stream),
    )?;
    validate_peer_process(&control_stream, runner.id())?;
    let control_channel =
        UnixStreamHostSetupChannel::from_host_guaranteed(control_stream, setup_deadline);
    crate::runtime::serve_association(
        broker,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            Ok(())
        },
        UnixStreamHostSetupChannel::into_active,
    )
}
