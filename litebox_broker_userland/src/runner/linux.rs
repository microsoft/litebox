// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::any::Any;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::ops::Range;
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::process::CpuTime;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_protocol::{ProcessId, SharedObjectToken};
use litebox_broker_transport_linux_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_broker_transport_linux_userland::memfd::{MemfdProcessImage, MemfdSharedMemory};
use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;
use litebox_broker_transport_linux_userland::unix_socket::{
    SenderIdentifyingStream, UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{
    PendingRunnerAssociation, RUNNER_POLL_INTERVAL, RunnerExit, RunnerKind, RunnerProcess,
    SupervisedRunners, UserlandProcessLauncher, accept_runner_channel, runner_has_exited,
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

    fn write_from_shared(
        &mut self,
        offset: u64,
        memory: &dyn Any,
        range: Range<usize>,
    ) -> Option<Result<(), BrokerError>> {
        let memory = memory.downcast_ref::<MemfdSharedMemory>()?;
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

/// Creates an empty child memory image, a memfd, which grows as it is written.
pub(crate) fn create_image(_capacity: u64) -> Result<Box<dyn ProcessImage>, BrokerError> {
    MemfdProcessImage::create()
        .map(|image| Box::new(RunnerProcessImage(image)) as Box<dyn ProcessImage>)
        .map_err(|_| BrokerError::OutOfMemory)
}

/// Makes `command` start its process with only the standard streams of the descriptors this
/// process may have inherited without close-on-exec.
///
/// A runner finds the broker through its control socket path and gets every broker descriptor
/// over it, at the lowest free numbers. A native fork-capable runner needs them at fixed numbers
/// just above the standard streams, so a stray descriptor there, such as one leaked by the
/// broker's own parent, would disable native fork. It would also leak a host descriptor into the
/// sandbox.
pub(super) fn inherit_only_standard_streams(command: &mut Command) {
    // SAFETY: The hook runs in the forked child before exec and only makes the async-signal-safe
    // `close_range` system call. Marking descriptors close-on-exec, rather than closing them,
    // keeps the descriptor through which `Command` reports a failed exec.
    unsafe {
        command.pre_exec(|| {
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(IoError::last_os_error());
            }
            Ok(())
        });
    }
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

/// The broker's control endpoint for one runner: listening for a spawned runner, connected for
/// an adopted clone, or closed.
pub(super) enum PlatformRunnerEndpoint {
    /// A spawned runner's endpoint, which listens at a path in a private directory.
    Listening {
        socket_path: PathBuf,
        listener: UnixListener,
        _directory: tempfile::TempDir,
    },
    /// The control stream the broker already holds for an adopted runner.
    Connected(UnixStream),
    /// An endpoint that was served or closed.
    Closed,
}

impl PlatformRunnerEndpoint {
    pub(super) fn create() -> IoResult<Self> {
        let directory = tempfile::Builder::new()
            .prefix("litebox-broker-userland-")
            .tempdir()?;
        let socket_path = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        Ok(Self::Listening {
            socket_path,
            listener,
            _directory: directory,
        })
    }

    /// Returns the path a spawned runner connects to, which is empty for an endpoint that does
    /// not listen.
    pub(super) fn control_channel(&self) -> &OsStr {
        match self {
            Self::Listening { socket_path, .. } => socket_path.as_os_str(),
            Self::Connected(_) | Self::Closed => OsStr::new(""),
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
            // Adoption authenticated the clone as the first sender on this stream.
            Self::Connected(stream) => Ok(UnixStreamHostSetupChannel::from_host_guaranteed(
                stream,
                setup_deadline,
            )),
            // The runner's one connection is accepted, so the listener closes with it.
            Self::Listening { listener, .. } => {
                accept_control_channel(&listener, runner, setup_deadline)
            }
            Self::Closed => Err(IoError::new(
                ErrorKind::NotConnected,
                "the runner control endpoint is closed",
            )),
        };
        serve_association(
            control_channel,
            runner,
            startup,
            setup_deadline,
            broker,
            launcher,
        )
    }

    pub(super) fn close(&mut self) {
        *self = Self::Closed;
    }
}

/// A natively cloned runner that the broker adopted, which it supervises through a pidfd.
pub(crate) struct AdoptedProcess {
    process_id: u32,
    /// Refers to the runner even after it exits and its ID is reused, so waiting for and
    /// signalling it never reach another process.
    pidfd: OwnedFd,
}

impl AdoptedProcess {
    pub(super) const fn id(&self) -> u32 {
        self.process_id
    }

    /// Reaps the runner if it exited, returning its exit.
    fn try_reap(&self) -> IoResult<Option<RunnerExit>> {
        Ok(
            wait_for_pidfd(self.pidfd.as_fd(), libc::WEXITED | libc::WNOHANG)?
                .map(|(info, usage)| runner_exit(exit_status(&info), &usage)),
        )
    }

    pub(super) fn kill(&mut self) -> IoResult<()> {
        // SAFETY: `pidfd` is a live pidfd, and the call reads no other pointers.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        } < 0
        {
            return Err(IoError::last_os_error());
        }
        Ok(())
    }

    /// Returns a pidfd for the runner, which becomes readable once it exits.
    fn pidfd(&self) -> IoResult<OwnedFd> {
        self.pidfd.try_clone()
    }
}

impl RunnerKind {
    /// Reaps the runner if it exited, returning its exit.
    ///
    /// Every runner, including a native fork clone, is a direct child of this broker and
    /// reaps no children of its own, so the usage reported when reaping it is the runner's own.
    /// A spawned runner is reaped here rather than through its `Child`, which cannot report
    /// usage; the caller never uses the `Child` to wait for or kill a reaped runner.
    pub(super) fn try_reap(&self) -> IoResult<Option<RunnerExit>> {
        let process = match self {
            Self::Spawned(process) => process,
            Self::Adopted(process) => return process.try_reap(),
        };
        let process_id =
            libc::pid_t::try_from(process.id()).map_err(|_| ErrorKind::InvalidInput)?;
        let mut status = 0;
        // SAFETY: A zeroed rusage is valid output storage for wait4.
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        // SAFETY: `process_id` names an unreaped direct child of this broker, and `status` and
        // `usage` are writable.
        let result =
            unsafe { libc::wait4(process_id, &raw mut status, libc::WNOHANG, &raw mut usage) };
        if result < 0 {
            return Err(IoError::last_os_error());
        }
        Ok((result != 0).then(|| runner_exit(ExitStatus::from_raw(status), &usage)))
    }
}

fn runner_exit(status: ExitStatus, usage: &libc::rusage) -> RunnerExit {
    let duration = |time: libc::timeval| {
        Duration::from_secs(u64::try_from(time.tv_sec).unwrap_or(0))
            + Duration::from_micros(u64::try_from(time.tv_usec).unwrap_or(0))
    };
    RunnerExit {
        status,
        cpu_time: CpuTime {
            user: duration(usage.ru_utime),
            system: duration(usage.ru_stime),
        },
    }
}

/// Waits, as `options` direct, for the child of this broker that `pidfd` refers to, returning
/// its state and resource usage if it exited, or `None` if it is still running under `WNOHANG`.
///
/// Fails with [`ErrorKind::PermissionDenied`] if `pidfd` refers to no unreaped child of this
/// broker.
fn wait_for_pidfd(
    pidfd: BorrowedFd<'_>,
    options: libc::c_int,
) -> IoResult<Option<(libc::siginfo_t, libc::rusage)>> {
    // SAFETY: A zeroed siginfo_t is valid output storage for waitid.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    // SAFETY: A zeroed rusage is valid output storage for waitid.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    // Unlike libc's wrapper, the system call also reports the child's resource usage.
    // SAFETY: `info` and `usage` are writable, and the call takes no other pointers.
    if unsafe {
        libc::syscall(
            libc::SYS_waitid,
            libc::P_PIDFD,
            pidfd.as_raw_fd(),
            &raw mut info,
            options,
            &raw mut usage,
        )
    } < 0
    {
        let error = IoError::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ECHILD) {
            not_a_child()
        } else {
            error
        });
    }
    // SAFETY: waitid initialized `info`, whose PID is zero if the child has not exited.
    Ok((unsafe { info.si_pid() } != 0).then_some((info, usage)))
}

/// Returns the exit status that `info`, which waitid filled in for an exited child, reports.
fn exit_status(info: &libc::siginfo_t) -> ExitStatus {
    // SAFETY: waitid filled in `info` for an exited child, which sets its status.
    let status = unsafe { info.si_status() };
    ExitStatus::from_raw(match info.si_code {
        libc::CLD_EXITED => (status & 0xff) << 8,
        libc::CLD_DUMPED => (status & 0x7f) | 0x80,
        _ => status & 0x7f,
    })
}

fn not_a_child() -> IoError {
    IoError::new(
        ErrorKind::PermissionDenied,
        "runner clone is not a child of the broker",
    )
}

/// Returns whether `error` reports that this process or the system ran out of descriptors.
pub(crate) fn is_out_of_descriptors(error: &IoError) -> bool {
    matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

/// The broker's end of a natively cloned runner's control connection, which
/// [`deliver_child_connection`] creates before the clone exists.
pub(crate) type ChildConnection = SenderIdentifyingStream;

/// Creates the control connection through which a native clone of `parent`'s runner will
/// associate, and sends the runner's end to that runner, which the clone inherits.
///
/// Returns the broker's end, for [`authenticate_clone`], and the token under which the runner
/// takes its end.
pub(crate) fn deliver_child_connection(
    senders: &SharedObjectSenders,
    parent: ProcessId,
) -> Result<(ChildConnection, SharedObjectToken), BrokerError> {
    let (connection, runner_end) = SenderIdentifyingStream::pair().map_err(|error| {
        litebox_util_log::warn!("cannot create a native fork control connection: {error}");
        BrokerError::ResourceExhausted
    })?;
    let token = senders.send(parent, runner_end.as_fd())?;
    Ok((connection, token))
}

/// The shared-object sender of each association the broker serves, through which it delivers
/// host objects, such as the control connections of its children's native clones, to the
/// association's runner.
pub(crate) struct SharedObjectSenders(Mutex<HashMap<ProcessId, SharedObjectSender>>);

/// Delivery to one runner through [`SharedObjectSenders`], which ends when this is dropped.
#[must_use = "dropping the registration stops delivery immediately"]
struct SharedObjectSenderRegistration<'a> {
    senders: &'a SharedObjectSenders,
    process: ProcessId,
}

impl Drop for SharedObjectSenderRegistration<'_> {
    fn drop(&mut self) {
        self.senders.lock().remove(&self.process);
    }
}

impl SharedObjectSenders {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ProcessId, SharedObjectSender>> {
        // Every update leaves the map consistent, so a panic elsewhere cannot corrupt it.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Delivers objects to `process`'s runner through `sender` until the returned registration
    /// is dropped.
    fn register(
        &self,
        process: ProcessId,
        sender: SharedObjectSender,
    ) -> SharedObjectSenderRegistration<'_> {
        self.lock().insert(process, sender);
        SharedObjectSenderRegistration {
            senders: self,
            process,
        }
    }

    /// Sends `object` to `process`'s runner, returning the token under which the runner takes
    /// it.
    fn send(
        &self,
        process: ProcessId,
        object: BorrowedFd<'_>,
    ) -> Result<SharedObjectToken, BrokerError> {
        // Sending under the lock keeps delivery from outliving the registration; the send never
        // blocks.
        self.lock()
            .get(&process)
            .ok_or(BrokerError::UnsupportedOperation)?
            .send(object)
            .map(SharedObjectToken)
            .map_err(|error| {
                litebox_util_log::warn!("cannot send a host object to a runner: {error}");
                if is_peer_closed_error(&error) {
                    BrokerError::PeerClosed
                } else {
                    BrokerError::ResourceExhausted
                }
            })
    }
}

/// A natively cloned runner that [`authenticate_clone`] found sending first on the control
/// connection the broker created for it.
pub(crate) struct AuthenticatedClone {
    process_id: u32,
    /// Refers to the clone, which had `process_id` when it was authenticated.
    pidfd: OwnedFd,
    connection: UnixStream,
}

/// Authenticates the natively cloned runner that `runner_descriptor` names as the first sender on
/// `connection` before `deadline`, returning it with a pidfd that [`adopt`] checks.
///
/// Where the kernel identifies senders only by process ID, the named clone is first pinned as a
/// running child of this broker, which keeps its ID from naming another process.
pub(super) fn authenticate_clone(
    runner_descriptor: Vec<u8>,
    connection: Option<ChildConnection>,
    deadline: Instant,
) -> IoResult<AuthenticatedClone> {
    let descriptor = ExistingRunnerDescriptor::decode(&runner_descriptor)?;
    let connection = connection.ok_or_else(|| {
        IoError::new(
            ErrorKind::PermissionDenied,
            "the runner clone has no control connection",
        )
    })?;
    let (connection, pidfd) =
        connection.verify_first_sender(descriptor.process_id, deadline, || {
            pin_running_child(descriptor.process_id)
        })?;
    Ok(AuthenticatedClone {
        process_id: descriptor.process_id,
        pidfd,
        connection,
    })
}

/// Returns a pidfd for `process_id` after checking that it names a running child of this broker,
/// which keeps the ID from being reused until this broker reaps it.
fn pin_running_child(process_id: u32) -> IoResult<OwnedFd> {
    let pid = libc::pid_t::try_from(process_id).map_err(|_| not_a_child())?;
    let pidfd = litebox_platform_linux_userland::process::pidfd_open(pid).map_err(|error| {
        if error.raw_os_error() == Some(libc::ESRCH) {
            not_a_child()
        } else {
            error
        }
    })?;
    // Checked after opening, so the pidfd pins a running child.
    ensure_running_child(pidfd.as_fd())?;
    Ok(pidfd)
}

/// Checks that `pidfd` refers to a running child of this broker, which keeps its ID from being
/// reused until this broker reaps it.
fn ensure_running_child(pidfd: BorrowedFd<'_>) -> IoResult<()> {
    // WNOWAIT leaves the exit status for the runner's supervisor to reap.
    if wait_for_pidfd(pidfd, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)?.is_some() {
        return Err(IoError::new(
            ErrorKind::BrokenPipe,
            "runner clone exited before adoption",
        ));
    }
    Ok(())
}

/// Adopts a natively cloned runner that [`authenticate_clone`] authenticated.
///
/// The caller must hold the lock under which runners become supervised, because the clone keeps
/// its process ID only while unreaped: authentication may wait, during which a runner supervised
/// under the clone's process ID could be reaped, deregistered, and its ID reused. Only
/// supervision reaps runners, so a clone whose pidfd still refers to a running child here, and
/// that is not supervised, keeps its process ID until the caller registers it.
pub(super) fn adopt(
    _parent: &Arc<Mutex<RunnerProcess>>,
    clone: AuthenticatedClone,
    supervised: &SupervisedRunners,
) -> IoResult<(RunnerProcess, PlatformRunnerEndpoint)> {
    let AuthenticatedClone {
        process_id,
        pidfd,
        connection,
    } = clone;
    if supervised.contains_key(&process_id) {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "runner process is already supervised",
        ));
    }
    ensure_running_child(pidfd.as_fd())?;
    Ok((
        RunnerProcess::new(RunnerKind::Adopted(AdoptedProcess { process_id, pidfd })),
        PlatformRunnerEndpoint::Connected(connection),
    ))
}

fn serve_association(
    control_channel: IoResult<UnixStreamHostSetupChannel>,
    runner: &Arc<Mutex<RunnerProcess>>,
    mut startup: PendingRunnerAssociation,
    setup_deadline: Instant,
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
    let (shared_objects, runner_shared_objects) = match SharedObjectSender::pair() {
        Ok(pair) => pair,
        Err(error) => {
            return AssociationOutcome {
                result: Err(error),
                abnormal: true,
            };
        }
    };
    // Delivery to this runner lasts while the association is served.
    let registration = launcher
        .shared_object_senders
        .register(startup.process.id(), shared_objects);
    let outcome = crate::runtime::serve_out_of_process_runner_association(
        startup,
        broker,
        control_channel,
        || MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE),
        MemfdSharedMemory::create_control_ring,
        // Moving `image` into this one-shot closure releases the broker's
        // snapshot as soon as setup ends; the runner owns its copy after that.
        move |channel, shared_memory, control_memory| {
            channel.send_memfd(shared_memory, Some(setup_deadline))?;
            channel.send_memfd(control_memory, Some(setup_deadline))?;
            channel
                .send_shared_object_channel(runner_shared_objects.as_fd(), Some(setup_deadline))?;
            let image = image.as_ref().map(|image| {
                &image
                    .image()
                    .as_any()
                    .downcast_ref::<RunnerProcessImage>()
                    .expect("the userland launcher creates every process image")
                    .0
            });
            channel.send_process_image(image, Some(setup_deadline))
        },
        UnixStreamHostSetupChannel::into_active,
        Arc::clone(&launcher),
    );
    drop(registration);
    outcome
}

fn accept_control_channel(
    control_listener: &UnixListener,
    runner: &Arc<Mutex<RunnerProcess>>,
    setup_deadline: Instant,
) -> IoResult<UnixStreamHostSetupChannel> {
    let control_stream = accept_runner_channel(
        setup_deadline,
        "control",
        || runner_has_exited(runner).map(|exited| exited.then(|| "exited".to_owned())),
        || control_listener.accept().map(|(stream, _)| stream),
        |remaining| wait_for_runner_event(runner, Some(control_listener), Some(remaining)),
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

/// Waits until the runner exits, `listener` becomes readable, or `timeout`
/// elapses. Callers recheck their own condition, so early returns are harmless.
pub(super) fn wait_for_runner_event(
    runner: &Arc<Mutex<RunnerProcess>>,
    listener: Option<&UnixListener>,
    timeout: Option<Duration>,
) -> IoResult<()> {
    let pidfd = {
        let mut runner = runner.lock().expect("runner process mutex poisoned");
        if runner.try_wait()?.is_some() {
            return Ok(());
        }
        match &runner.kind {
            RunnerKind::Adopted(process) => process.pidfd().ok(),
            RunnerKind::Spawned(process) => {
                // Holding the lock keeps the runner unreaped, so its PID cannot be
                // reused before the pidfd pins the process.
                let pid =
                    libc::pid_t::try_from(process.id()).map_err(|_| ErrorKind::InvalidInput)?;
                litebox_platform_linux_userland::process::pidfd_open(pid).ok()
            }
        }
    };
    // Without a pidfd, such as when this process is out of descriptors, poll for exit.
    let timeout = match pidfd {
        Some(_) => timeout,
        None => Some(timeout.map_or(RUNNER_POLL_INTERVAL, |t| t.min(RUNNER_POLL_INTERVAL))),
    };
    let timeout_ms = timeout.map_or(-1, |timeout| {
        i32::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX)
    });
    // `poll` ignores entries with negative descriptors.
    let mut fds = [
        pidfd.as_ref().map_or(-1, AsRawFd::as_raw_fd),
        listener.map_or(-1, AsRawFd::as_raw_fd),
    ]
    .map(|fd| libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    });
    // SAFETY: `fds` is a valid, writable array of `fds.len()` entries whose
    // descriptors stay open for the duration of the call.
    let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if result < 0 {
        let error = IoError::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::{Child, Stdio};

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    }

    fn descriptor(process_id: u32) -> Vec<u8> {
        ExistingRunnerDescriptor { process_id }.encode().unwrap()
    }

    /// Waits for `process_id`, a child of this process, to exit, leaving it unreaped.
    fn wait_for_exit_without_reaping(process_id: u32) {
        // SAFETY: A zeroed siginfo_t is valid output storage for waitid.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `info` is writable. WNOWAIT waits for the exit without reaping the child.
        let waited = unsafe {
            libc::waitid(
                libc::P_PID,
                process_id,
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(waited, 0, "{}", IoError::last_os_error());
    }

    /// Spawns a child that, holding `runner_end`, sends once admitted, then runs until killed if
    /// `linger`.
    fn spawn_sender(runner_end: UnixStream, linger: bool) -> Child {
        let input = runner_end.try_clone().unwrap();
        let script = if linger {
            "head -c 1 >/dev/null && echo x && exec sleep 30"
        } else {
            "head -c 1 >/dev/null && echo x"
        };
        Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::from(OwnedFd::from(input)))
            .stdout(Stdio::from(OwnedFd::from(runner_end)))
            .spawn()
            .unwrap()
    }

    #[test]
    fn runners_inherit_only_standard_streams() {
        let mut pipe = [0; 2];
        // SAFETY: `pipe` has room for both ends. Without `O_CLOEXEC`, a plain spawn would leak
        // them into the child.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        // SAFETY: `pipe` returned two new descriptors that nothing else owns.
        let ends = pipe.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
        let leaked = ends[1].as_raw_fd();
        let check = format!("[ ! -e /proc/self/fd/{leaked} ]");
        let spawn = |isolate: bool| {
            let mut command = Command::new("sh");
            command.args(["-c", &check]);
            if isolate {
                inherit_only_standard_streams(&mut command);
            }
            command.status().unwrap().success()
        };
        assert!(
            !spawn(false),
            "the test descriptor must otherwise be inherited"
        );
        assert!(spawn(true));
    }

    #[test]
    fn child_connections_are_delivered_to_registered_runners() {
        use std::io::{Read as _, Write as _};

        let senders = SharedObjectSenders::new();
        let parent = ProcessId(1);
        // A process whose runner cannot be sent objects receives none.
        assert!(matches!(
            deliver_child_connection(&senders, parent),
            Err(BrokerError::UnsupportedOperation)
        ));

        let (sender, runner) = SharedObjectSender::pair().unwrap();
        let channel =
            litebox_platform_linux_userland::shared_objects::SharedObjectChannel::new(runner);
        let registration = senders.register(parent, sender);
        let (broker_end, token) = deliver_child_connection(&senders, parent).unwrap();
        let runner_end = UnixStream::from(channel.take(token.0).unwrap());
        // The runner's end, once admitted, carries what its holder sends to the broker's end.
        let holder = std::thread::spawn(move || {
            litebox_broker_transport_linux_userland::unix_socket::wait_for_broker_admission(
                &runner_end,
            )
            .unwrap();
            (&runner_end).write_all(b"x").unwrap();
            runner_end
        });
        let own = std::process::id();
        let (mut broker_end, _pidfd) = broker_end
            .verify_first_sender(own, Instant::now() + Duration::from_secs(5), || {
                litebox_platform_linux_userland::process::pidfd_open(
                    libc::pid_t::try_from(own).unwrap(),
                )
            })
            .unwrap();
        let mut byte = [0];
        broker_end.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
        let runner_end = holder.join().unwrap();

        drop(registration);
        assert_eq!(
            senders.send(parent, runner_end.as_fd()),
            Err(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn only_running_children_are_pinned() {
        let mut child = sleeper();
        pin_running_child(child.id()).unwrap();

        // A child that exited stays this broker's unreaped child, so its process ID is never
        // reused, and it is rejected as exited.
        child.kill().unwrap();
        wait_for_exit_without_reaping(child.id());
        assert_eq!(
            pin_running_child(child.id()).unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
        child.wait().unwrap();

        // PID 1 is never this broker's child.
        assert_eq!(
            pin_running_child(1).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn clones_are_adopted_only_as_running_children_that_sent_first() {
        use std::io::Write as _;

        let deadline = || Instant::now() + Duration::from_secs(5);
        let parent = Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Spawned(
            sleeper(),
        ))));
        let adopted = |process_id, broker_end| {
            authenticate_clone(descriptor(process_id), broker_end, deadline())
                .and_then(|clone| adopt(&parent, clone, &SupervisedRunners::new()))
        };

        // The clone sends once admitted, and is adopted while it runs.
        let (broker_end, runner_end) = SenderIdentifyingStream::pair().unwrap();
        let mut clone = spawn_sender(runner_end, true);
        let (runner, _) = adopted(clone.id(), Some(broker_end)).unwrap();
        assert_eq!(runner.id(), clone.id());
        clone.kill().unwrap();
        clone.wait().unwrap();

        // A sender that is not this broker's child, such as one its parent runner forked.
        let (broker_end, mut runner_end) = SenderIdentifyingStream::pair().unwrap();
        runner_end.write_all(b"x").unwrap();
        assert_eq!(
            adopted(std::process::id(), Some(broker_end))
                .err()
                .unwrap()
                .kind(),
            ErrorKind::PermissionDenied
        );

        // A clone without a control connection has nothing to authenticate on.
        assert_eq!(
            adopted(std::process::id(), None).err().unwrap().kind(),
            ErrorKind::PermissionDenied
        );

        parent.lock().unwrap().kill().unwrap();
        super::super::wait_for_runner_exit(&parent).unwrap();
    }

    #[test]
    fn adoption_rejects_supervised_or_no_longer_running_clones() {
        let parent = Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Spawned(
            sleeper(),
        ))));
        let mut child = sleeper();
        let child_id = child.id();
        let pin = || {
            litebox_platform_linux_userland::process::pidfd_open(child_id.try_into().unwrap())
                .unwrap()
        };
        let clone = |pidfd| AuthenticatedClone {
            process_id: child_id,
            pidfd,
            connection: UnixStream::pair().unwrap().0,
        };
        let error = adopt(
            &parent,
            clone(pin()),
            &SupervisedRunners::from([(child_id, 1)]),
        )
        .err()
        .expect("a supervised runner must not be adopted again");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        let (runner, endpoint) = adopt(&parent, clone(pin()), &SupervisedRunners::new()).unwrap();
        assert_eq!(runner.id(), child_id);
        assert!(matches!(endpoint, PlatformRunnerEndpoint::Connected(_)));

        // A clone that exited, or whose supervisor reaped it while it authenticated, so that its
        // process ID may now name another process, is rejected.
        let pinned = pin();
        child.kill().unwrap();
        wait_for_exit_without_reaping(child_id);
        let error = adopt(&parent, clone(pin()), &SupervisedRunners::new())
            .err()
            .expect("an exited clone must not be adopted");
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        child.wait().unwrap();
        let error = adopt(&parent, clone(pinned), &SupervisedRunners::new())
            .err()
            .expect("a reaped clone must not be adopted");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);

        parent.lock().unwrap().kill().unwrap();
        super::super::wait_for_runner_exit(&parent).unwrap();
    }

    #[test]
    fn adopted_runners_are_waited_for_and_killed_through_their_pidfd() {
        use std::io::Write as _;

        let parent = Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Spawned(
            sleeper(),
        ))));
        let adopt_child = |child: &Child| {
            let pidfd = litebox_platform_linux_userland::process::pidfd_open(
                child.id().try_into().unwrap(),
            )
            .unwrap();
            let clone = AuthenticatedClone {
                process_id: child.id(),
                pidfd,
                connection: UnixStream::pair().unwrap().0,
            };
            adopt(&parent, clone, &SupervisedRunners::new()).unwrap().0
        };
        let wait = |runner: &mut RunnerProcess| loop {
            if let Some(exit) = runner.try_wait().unwrap() {
                return exit;
            }
            std::thread::sleep(Duration::from_millis(1));
        };

        #[expect(clippy::zombie_processes, reason = "the adopted runner reaps it")]
        let killed = sleeper();
        let mut runner = adopt_child(&killed);
        assert_eq!(runner.try_wait().unwrap(), None);
        runner.kill().unwrap();
        let exit = wait(&mut runner);
        assert_eq!(exit.status.signal(), Some(libc::SIGKILL));
        // Once reaped, the runner keeps its exit and is not signalled again.
        runner.kill().unwrap();
        assert_eq!(runner.try_wait().unwrap(), Some(exit));

        let (mut release, held) = UnixStream::pair().unwrap();
        #[expect(clippy::zombie_processes, reason = "the adopted runner reaps it")]
        let exiting = Command::new("sh")
            .args([
                "-c",
                "head -c 1 >/dev/null; i=0; while [ $i -lt 200000 ]; do i=$((i + 1)); done; exit 3",
            ])
            .stdin(Stdio::from(OwnedFd::from(held)))
            .spawn()
            .unwrap();
        let mut runner = adopt_child(&exiting);
        release.write_all(b"x").unwrap();
        let exit = wait(&mut runner);
        assert_eq!(exit.status.code(), Some(3));
        assert!(exit.cpu_time.user + exit.cpu_time.system > Duration::ZERO);

        parent.lock().unwrap().kill().unwrap();
        super::super::wait_for_runner_exit(&parent).unwrap();
    }

    #[test]
    fn reaping_reports_the_runner_cpu_time() {
        let busy = Command::new("sh")
            .args(["-c", "i=0; while [ $i -lt 200000 ]; do i=$((i + 1)); done"])
            .spawn()
            .unwrap();
        let runner = Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Spawned(busy))));
        let exit = super::super::wait_for_runner_exit(&runner).unwrap();
        assert!(exit.status.success());
        assert!(exit.cpu_time.user + exit.cpu_time.system > Duration::ZERO);
        // The cached exit is reported again without reaping, and killing it is a no-op.
        let mut runner = runner.lock().unwrap();
        assert_eq!(runner.try_wait().unwrap(), Some(exit));
        runner.kill().unwrap();
    }
}
