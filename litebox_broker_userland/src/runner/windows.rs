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
use litebox_broker_transport_windows_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_broker_transport_windows_userland::named_pipe::{
    WindowsNamedPipeHostSetupChannel, WindowsNamedPipeListener, validate_client_process,
};
use litebox_broker_transport_windows_userland::process_image::WindowsProcessImage;
use litebox_broker_transport_windows_userland::shared_memory::WindowsSharedMemory;

use super::{
    PendingRunnerAssociation, RUNNER_POLL_INTERVAL, RunnerProcess, SupervisedRunners,
    UserlandProcessLauncher, accept_runner_channel, runner_has_exited,
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
        // A process can exit with `STILL_ACTIVE` as its code, so check the handle's signaled
        // state rather than comparing the exit code against that sentinel.
        // SAFETY: `handle` owns a live process handle; a zero timeout only polls.
        match unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.handle.as_raw_handle(),
                0,
            )
        } {
            windows_sys::Win32::Foundation::WAIT_OBJECT_0 => {}
            windows_sys::Win32::Foundation::WAIT_TIMEOUT => return Ok(None),
            _ => return Err(std::io::Error::last_os_error()),
        }
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
        Ok(Some(ExitStatus::from_raw(exit_code)))
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

/// The broker's control endpoint for one runner: a named pipe listening for the runner, or
/// closed.
pub(super) enum PlatformRunnerEndpoint {
    Listening {
        pipe_name: OsString,
        listener: WindowsNamedPipeListener,
    },
    /// An endpoint that was served or closed.
    Closed,
}

impl PlatformRunnerEndpoint {
    pub(super) fn create() -> IoResult<Self> {
        let pipe_name = unique_control_pipe_name();
        Self::create_at(pipe_name)
    }

    fn create_at(pipe_name: OsString) -> IoResult<Self> {
        let listener = WindowsNamedPipeListener::bind(&pipe_name)?;
        Ok(Self::Listening {
            pipe_name,
            listener,
        })
    }

    /// Returns the pipe name a runner connects to, which is empty for a closed endpoint.
    pub(super) fn control_channel(&self) -> &std::ffi::OsStr {
        match self {
            Self::Listening { pipe_name, .. } => pipe_name,
            Self::Closed => std::ffi::OsStr::new(""),
        }
    }

    pub(super) fn serve(
        &mut self,
        runner: &Arc<Mutex<RunnerProcess>>,
        startup: PendingRunnerAssociation,
        setup_deadline: Instant,
        broker: BrokerCore,
        launcher: Arc<UserlandProcessLauncher>,
    ) -> AssociationOutcome {
        let control_channel = match std::mem::replace(self, Self::Closed) {
            // The runner's one connection is accepted, so the listener closes with it.
            Self::Listening { mut listener, .. } => {
                accept_control_channel(&mut listener, runner, setup_deadline)
            }
            Self::Closed => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "the runner control endpoint is closed",
            )),
        };
        serve_association(control_channel, runner, startup, broker, launcher)
    }

    pub(super) fn close(&mut self) {
        *self = Self::Closed;
    }
}

/// The broker's end of a natively cloned runner's control connection: never created, as Windows
/// clones connect through the named pipe in their descriptor.
pub(crate) type ChildConnection = core::convert::Infallible;

/// Delivers no host objects: Windows runners take every broker object through their association.
pub(crate) struct SharedObjectSenders;

impl SharedObjectSenders {
    pub(crate) const fn new() -> Self {
        Self
    }
}

/// Fails with [`BrokerError::UnsupportedOperation`], as Windows clones connect through the named
/// pipe in their descriptor rather than a connection the broker creates.
pub(crate) fn deliver_child_connection(
    _senders: &SharedObjectSenders,
    _parent: litebox_broker_protocol::ProcessId,
) -> Result<(ChildConnection, litebox_broker_protocol::SharedObjectToken), BrokerError> {
    Err(BrokerError::UnsupportedOperation)
}

/// Returns whether `error` reports that this process or the system ran out of handles.
pub(crate) fn is_out_of_descriptors(error: &std::io::Error) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_NO_SYSTEM_RESOURCES, ERROR_TOO_MANY_OPEN_FILES};

    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .is_some_and(|code| code == ERROR_TOO_MANY_OPEN_FILES || code == ERROR_NO_SYSTEM_RESOURCES)
}

/// A natively cloned Windows runner's encoded descriptor, which [`adopt`] authenticates.
pub(crate) struct AuthenticatedClone(Vec<u8>);

/// Checks nothing, as [`adopt`] binds a Windows clone through its handle, which it duplicates
/// from the parent's handle table, and the clone connects through the named pipe in its
/// descriptor rather than a connection the broker created.
#[expect(
    clippy::unnecessary_wraps,
    reason = "shares the signature of the Linux check, which can fail"
)]
pub(super) fn authenticate_clone(
    runner_descriptor: Vec<u8>,
    _connection: Option<ChildConnection>,
    _deadline: Instant,
) -> IoResult<AuthenticatedClone> {
    Ok(AuthenticatedClone(runner_descriptor))
}

/// Adopts a runner natively cloned by `parent` and binds the control pipe it will connect to.
///
/// The clone's handle is duplicated from `parent`'s handle table, and the clone must not be
/// supervised already (`supervised` holds the host process IDs of supervised runners).
pub(super) fn adopt(
    parent: &Arc<Mutex<RunnerProcess>>,
    clone: AuthenticatedClone,
    supervised: &SupervisedRunners,
) -> IoResult<(RunnerProcess, PlatformRunnerEndpoint)> {
    let parent = parent.lock().expect("parent runner process mutex poisoned");
    let descriptor = ExistingRunnerDescriptor::decode(&clone.0, parent.id())?;
    if supervised.contains_key(&descriptor.process_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "runner process is already supervised",
        ));
    }
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
    let endpoint = PlatformRunnerEndpoint::create_at(descriptor.control_channel)?;
    Ok((
        RunnerProcess::Adopted(AdoptedProcess::new(duplicated, process_id)),
        endpoint,
    ))
}

fn serve_association(
    control_channel: IoResult<WindowsNamedPipeHostSetupChannel>,
    runner: &Arc<Mutex<RunnerProcess>>,
    mut startup: PendingRunnerAssociation,
    broker: BrokerCore,
    launcher: Arc<UserlandProcessLauncher>,
) -> AssociationOutcome {
    let image = startup.take_image();
    let shutdown_was_expected = startup.process.shutdown_was_expected();
    let control_channel = match control_channel {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_waiting_child() -> std::process::Child {
        std::process::Command::new("cmd")
            .args(["/c", "ping -n 30 127.0.0.1 >nul"])
            .spawn()
            .unwrap()
    }

    #[test]
    fn adoption_rejects_supervised_processes() {
        let parent = Arc::new(Mutex::new(RunnerProcess::Spawned(spawn_waiting_child())));
        let parent_id = parent.lock().unwrap().id();
        let descriptor = ExistingRunnerDescriptor {
            process_handle: 4,
            process_id: parent_id,
            control_channel: format!(
                r"\\.\pipe\litebox-native-runner-{parent_id}-{}",
                "0".repeat(32)
            )
            .into(),
        }
        .encode()
        .unwrap();
        let error = adopt(
            &parent,
            AuthenticatedClone(descriptor),
            &SupervisedRunners::from([(parent_id, 1)]),
        )
        .err()
        .expect("a supervised runner must not be adopted again");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let RunnerProcess::Spawned(parent) = &mut *parent.lock().unwrap() else {
            unreachable!();
        };
        parent.kill().unwrap();
        parent.wait().unwrap();
    }

    #[test]
    fn adopted_process_reports_still_active_exit_code() {
        let child = std::process::Command::new("cmd")
            .args(["/c", "exit 259"])
            .spawn()
            .unwrap();
        let process_id = child.id();
        let process = AdoptedProcess::new(OwnedHandle::from(child), process_id);
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "exited process was never reaped");
            std::thread::sleep(RUNNER_POLL_INTERVAL);
        };
        assert_eq!(status.code(), Some(259));
    }
}
