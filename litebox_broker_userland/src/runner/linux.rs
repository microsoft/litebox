// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::any::Any;
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_linux_userland::memfd::{MemfdProcessImage, MemfdSharedMemory};
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{
    PendingRunnerAssociation, UserlandProcessLauncher, accept_runner_channel, runner_has_exited,
};
use crate::runtime::{AssociationOutcome, is_peer_closed_error};

/// Memory image passed to a runner as a sealed memfd.
struct RunnerProcessImage(MemfdProcessImage);

impl ProcessImage for RunnerProcessImage {
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), BrokerError> {
        self.0
            .write(offset, data)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

pub(crate) fn create_process_image() -> Result<Box<dyn ProcessImage>, BrokerError> {
    MemfdProcessImage::create()
        .map(|image| Box::new(RunnerProcessImage(image)) as Box<dyn ProcessImage>)
        .map_err(|_| BrokerError::OutOfMemory)
}

/// Makes `command` start its process with address-space layout randomization
/// disabled.
pub(super) fn disable_aslr(command: &mut Command) {
    // SAFETY: The hook runs in the forked child before exec and only makes
    // async-signal-safe `personality` system calls.
    unsafe {
        command.pre_exec(|| {
            let persona = libc::personality(0xffff_ffff);
            if persona == -1
                || libc::personality(
                    (persona as libc::c_ulong) | libc::ADDR_NO_RANDOMIZE as libc::c_ulong,
                ) == -1
            {
                return Err(IoError::last_os_error());
            }
            Ok(())
        });
    }
}

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
        startup: PendingRunnerAssociation,
        setup_deadline: Instant,
        broker: BrokerCore,
        launcher: Arc<UserlandProcessLauncher>,
    ) -> AssociationOutcome {
        serve_association(
            self.listener
                .as_ref()
                .expect("a live runner instance must own its control listener"),
            runner,
            startup,
            setup_deadline,
            broker,
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
    mut startup: PendingRunnerAssociation,
    setup_deadline: Instant,
    broker: BrokerCore,
    launcher: Arc<UserlandProcessLauncher>,
) -> AssociationOutcome {
    let image = startup.take_image().map(|image| {
        image
            .into_any()
            .downcast::<RunnerProcessImage>()
            .expect("the userland launcher creates every process image")
    });
    let shutdown_was_expected = startup.process.shutdown_was_expected();
    let control_channel = match accept_control_channel(control_listener, runner, setup_deadline) {
        Ok(connection) => connection,
        Err(error) => {
            let abnormal = !(runner_has_exited(runner).unwrap_or(false)
                || shutdown_was_expected && is_peer_closed_error(&error));
            return AssociationOutcome {
                result: Err(error),
                abnormal,
            };
        }
    };
    crate::runtime::serve_out_of_process_runner_association(
        startup,
        broker,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            channel.send_process_image(image.as_ref().map(|image| &image.0), Some(setup_deadline))
        },
        UnixStreamHostSetupChannel::into_active,
        launcher,
    )
}

fn accept_control_channel(
    control_listener: &UnixListener,
    runner: &Arc<Mutex<Child>>,
    setup_deadline: Instant,
) -> IoResult<UnixStreamHostSetupChannel> {
    let control_stream = accept_runner_channel(
        setup_deadline,
        "control",
        || runner_has_exited(runner).map(|exited| exited.then(|| "exited".to_owned())),
        || control_listener.accept().map(|(stream, _)| stream),
    )?;
    {
        let mut runner = runner.lock().expect("runner process mutex poisoned");
        if runner.try_wait()?.is_some() {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                "runner exited before peer authentication",
            ));
        }
        validate_peer_process(&control_stream, runner.id())?;
    }
    Ok(UnixStreamHostSetupChannel::from_host_guaranteed(
        control_stream,
        setup_deadline,
    ))
}
