// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::any::Any;
use std::ffi::OsString;
use std::io::Result as IoResult;
use std::ops::Range;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_windows_userland::existing_runner::ExistingRunnerLaunchDescriptor;
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, validate_client_process,
};
use litebox_broker_transport_windows_userland::process_image::WindowsProcessImage;
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;

use super::{
    PendingRunnerAssociation, RUNNER_POLL_INTERVAL, RunnerProcess, UserlandProcessLauncher,
    accept_runner_channel, runner_has_exited,
};
use crate::runtime::{AssociationOutcome, is_peer_closed_error};

pub(crate) struct AdoptedProcess {
    handle: OwnedHandle,
    process_id: u32,
}

impl AdoptedProcess {
    pub(super) const fn new(handle: OwnedHandle, process_id: u32) -> Self {
        Self { handle, process_id }
    }

    pub(super) const fn id(&self) -> u32 {
        self.process_id
    }

    pub(super) fn try_wait(&self) -> IoResult<Option<ExitStatus>> {
        let mut exit_code = 0;
        // SAFETY: `handle` owns a live process handle and `exit_code` is writable.
        if unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(
                self.handle.as_raw_handle(),
                &raw mut exit_code,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(
            (exit_code != windows_sys::Win32::Foundation::STILL_ACTIVE.cast_unsigned())
                .then(|| ExitStatus::from_raw(exit_code)),
        )
    }

    pub(super) fn kill(&self) -> IoResult<()> {
        // SAFETY: `handle` owns a process handle with termination rights.
        if unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(self.handle.as_raw_handle(), 1)
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl RunnerProcess {
    fn as_raw_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        match self {
            Self::Spawned(process) => process.as_raw_handle(),
            Self::Adopted(process) => process.handle.as_raw_handle(),
        }
    }
}

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
        Self::create_at(pipe_name)
    }

    pub(super) fn create_at(pipe_name: OsString) -> IoResult<Self> {
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
        runner: &Arc<Mutex<RunnerProcess>>,
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

pub(super) fn adopt_process(
    parent: &Arc<Mutex<RunnerProcess>>,
    descriptor: &ExistingRunnerLaunchDescriptor,
) -> IoResult<RunnerProcess> {
    let parent = parent.lock().expect("parent runner process mutex poisoned");
    let source_handle = usize::try_from(descriptor.process_handle).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "existing runner handle does not fit the broker pointer width",
        )
    })?;
    let mut duplicated = std::ptr::null_mut();
    // SAFETY: `parent` is live. DuplicateHandle validates the untrusted source value in that
    // process's handle table and creates a new broker-owned handle.
    if unsafe {
        windows_sys::Win32::Foundation::DuplicateHandle(
            parent.as_raw_handle(),
            source_handle as _,
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            &raw mut duplicated,
            0,
            0,
            windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: DuplicateHandle returned a newly owned process handle.
    let duplicated = unsafe { OwnedHandle::from_raw_handle(duplicated) };
    // SAFETY: `duplicated` is a valid owned handle. GetProcessId returns zero for other object
    // types or process handles without sufficient access, both of which are rejected below.
    let process_id =
        unsafe { windows_sys::Win32::System::Threading::GetProcessId(duplicated.as_raw_handle()) };
    if process_id == 0 || process_id != descriptor.process_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "existing runner process ID does not match its handle",
        ));
    }
    Ok(RunnerProcess::Adopted(AdoptedProcess::new(
        duplicated, process_id,
    )))
}

fn serve_association(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &Arc<Mutex<RunnerProcess>>,
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
            channel.send_process_image(image.map(|image| (image, runner_process)))
        },
        WindowsNamedPipeHostSetupChannel::into_active,
        launcher,
    )
}

fn accept_control_channel(
    control_listener: &mut WindowsNamedPipeListener,
    runner: &Arc<Mutex<RunnerProcess>>,
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
    _runner: &Arc<Mutex<RunnerProcess>>,
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
