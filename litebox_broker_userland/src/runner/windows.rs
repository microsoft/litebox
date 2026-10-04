// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::any::Any;
use std::ffi::OsString;
use std::io::Result as IoResult;
use std::ops::Range;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, validate_client_process,
};
use litebox_broker_transport_windows_userland::process_image::WindowsProcessImage;
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;

use super::{
    PendingRunnerAssociation, RUNNER_POLL_INTERVAL, UserlandProcessLauncher, accept_runner_channel,
    runner_has_exited,
};
use crate::runtime::{AssociationOutcome, is_peer_closed_error};

/// A child's memory image held for its runner.
struct RunnerProcessImage(WindowsProcessImage);

impl ProcessImage for RunnerProcessImage {
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), BrokerError> {
        self.0
            .write(offset, data)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    fn write_from_shared(
        &mut self,
        offset: u64,
        memory: &dyn Any,
        range: Range<usize>,
    ) -> Option<Result<(), BrokerError>> {
        let memory = memory.downcast_ref::<WindowsSharedMemory>()?;
        Some(
            self.0
                .write_from_shared(offset, memory, range)
                .map_err(|_| BrokerError::OutOfMemory),
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Creates an empty child memory image, a section that reserves `capacity`
/// bytes and commits them as they are written.
pub(crate) fn create_image(capacity: u64) -> Result<Box<dyn ProcessImage>, BrokerError> {
    let capacity = usize::try_from(capacity).map_err(|_| BrokerError::OutOfMemory)?;
    WindowsProcessImage::create(capacity)
        .map(|image| Box::new(RunnerProcessImage(image)) as Box<dyn ProcessImage>)
        .map_err(|_| BrokerError::OutOfMemory)
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
        startup: PendingRunnerAssociation,
        setup_deadline: Instant,
        broker: BrokerCore,
        launcher: Arc<UserlandProcessLauncher>,
    ) -> AssociationOutcome {
        serve_association(
            self.listener
                .as_mut()
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
    }
}

fn serve_association(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &Arc<Mutex<Child>>,
    mut startup: PendingRunnerAssociation,
    setup_deadline: Instant,
    broker: BrokerCore,
    launcher: Arc<UserlandProcessLauncher>,
) -> AssociationOutcome {
    let image = startup.take_image();
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
    let runner_process = runner
        .lock()
        .expect("runner process mutex poisoned")
        .as_raw_handle();
    crate::runtime::serve_out_of_process_runner_association(
        startup,
        broker,
        control_channel,
        || WindowsSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        WindowsSharedMemory::create_control_ring,
        // Moving `image` into this one-shot closure releases the broker's
        // snapshot as soon as setup ends; the runner owns its copy after that.
        move |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, runner_process)?;
            channel.send_shared_memory(control_memory, runner_process)?;
            let image = image.as_ref().map(|image| {
                &image
                    .image()
                    .as_any()
                    .downcast_ref::<RunnerProcessImage>()
                    .expect("the userland launcher creates every process image")
                    .0
            });
            channel.send_process_image(image, runner_process)
        },
        WindowsNamedPipeHostSetupChannel::into_active,
        launcher,
    )
}

fn accept_control_channel(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &Arc<Mutex<Child>>,
    setup_deadline: Instant,
) -> IoResult<WindowsNamedPipeHostSetupChannel> {
    let control_stream = accept_runner_channel(
        setup_deadline,
        "control",
        || runner_has_exited(runner).map(|exited| exited.then(|| "exited".to_owned())),
        || control_listener.try_accept(),
        |remaining| wait_for_runner_event(runner, None, Some(remaining)),
    )?;
    let runner_id = runner.lock().expect("runner process mutex poisoned").id();
    validate_client_process(&control_stream, runner_id)?;
    Ok(WindowsNamedPipeHostSetupChannel::from_host_guaranteed(
        control_stream,
        setup_deadline,
    ))
}

/// Sleeps for at most [`RUNNER_POLL_INTERVAL`] before callers recheck the
/// runner and listener.
#[expect(
    clippy::unnecessary_wraps,
    reason = "callers share the fallible Linux signature"
)]
pub(super) fn wait_for_runner_event(
    _runner: &Arc<Mutex<Child>>,
    _listener: Option<&WindowsNamedPipeListener>,
    timeout: Option<Duration>,
) -> IoResult<()> {
    std::thread::sleep(timeout.map_or(RUNNER_POLL_INTERVAL, |t| t.min(RUNNER_POLL_INTERVAL)));
    Ok(())
}

fn unique_control_pipe_name() -> OsString {
    let process_id = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(r"\\.\pipe\litebox-broker-{process_id}-{nonce}").into()
}
