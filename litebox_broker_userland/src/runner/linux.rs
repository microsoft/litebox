// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::any::Any;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::ops::Range;
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_protocol::{ProcessId, SharedObjectToken};
use litebox_broker_transport_linux_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_broker_transport_linux_userland::memfd::{MemfdProcessImage, MemfdSharedMemory};
use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, admit_sender_process, enable_sender_credentials,
    validate_peer_process,
};

use super::{
    PendingRunnerAssociation, RUNNER_POLL_INTERVAL, RunnerProcess, SupervisedRunners,
    UserlandProcessLauncher, accept_runner_channel, runner_has_exited,
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

pub(super) struct PlatformRunnerEndpoint {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
    directory: Option<tempfile::TempDir>,
    /// Control stream the broker already holds for an adopted runner, which never listens.
    connected: Option<UnixStream>,
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
            connected: None,
        })
    }

    pub(super) fn control_channel(&self) -> &OsStr {
        self.socket_path.as_os_str()
    }

    pub(super) fn serve(
        &mut self,
        runner: &Arc<Mutex<RunnerProcess>>,
        startup: PendingRunnerAssociation,
        setup_deadline: Instant,
        broker: BrokerCore,
        launcher: Arc<UserlandProcessLauncher>,
    ) -> AssociationOutcome {
        let control_channel = match self.connected.take() {
            // Adoption authenticated the clone that holds this stream's other end.
            Some(stream) => Ok(UnixStreamHostSetupChannel::from_host_guaranteed(
                stream,
                setup_deadline,
            )),
            None => accept_control_channel(
                self.listener
                    .as_ref()
                    .expect("a live spawned runner instance must own its control listener"),
                runner,
                setup_deadline,
            ),
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
        self.listener.take();
        self.directory.take();
        self.connected.take();
    }
}

pub(crate) struct AdoptedProcess {
    process_id: u32,
    status: Option<ExitStatus>,
}

impl AdoptedProcess {
    pub(super) const fn id(&self) -> u32 {
        self.process_id
    }

    pub(super) fn try_wait(&mut self) -> IoResult<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let process_id =
            libc::pid_t::try_from(self.process_id).map_err(|_| ErrorKind::InvalidInput)?;
        let mut status = 0;
        // SAFETY: `process_id` names a direct child of this broker and `status` is writable.
        let result = unsafe { libc::waitpid(process_id, &raw mut status, libc::WNOHANG) };
        if result < 0 {
            return Err(IoError::last_os_error());
        }
        if result == 0 {
            return Ok(None);
        }
        let status = ExitStatus::from_raw(status);
        self.status = Some(status);
        Ok(Some(status))
    }

    pub(super) fn kill(&mut self) -> IoResult<()> {
        if self.status.is_some() {
            return Ok(());
        }
        let process_id =
            libc::pid_t::try_from(self.process_id).map_err(|_| ErrorKind::InvalidInput)?;
        // SAFETY: Only this owner reaps the adopted child, so its PID cannot be reused yet.
        if unsafe { libc::kill(process_id, libc::SIGKILL) } < 0 {
            return Err(IoError::last_os_error());
        }
        Ok(())
    }
}

/// The broker's end of a natively cloned runner's control connection, which
/// [`create_child_connection`] creates before the clone exists.
pub(crate) type ChildConnection = UnixStream;

/// Creates the control connection through which a native clone of a runner will associate.
///
/// Returns the broker's end, which records the credentials of whoever sends on it, for
/// [`authenticate_clone`], and the runner's end, which the clone inherits from its parent.
pub(crate) fn create_child_connection() -> Result<(ChildConnection, UnixStream), BrokerError> {
    let (broker_end, runner_end) =
        UnixStream::pair().map_err(|_| BrokerError::ResourceExhausted)?;
    enable_sender_credentials(&broker_end).map_err(|_| BrokerError::ResourceExhausted)?;
    Ok((broker_end, runner_end))
}

/// The shared-object sender of each association the broker serves, through which it delivers
/// host objects, such as the control connections of its children's native clones, to the
/// association's runner.
#[derive(Default)]
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
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ProcessId, SharedObjectSender>> {
        self.0.lock().expect("shared-object senders mutex poisoned")
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
    pub(crate) fn send(
        &self,
        process: ProcessId,
        object: BorrowedFd<'_>,
    ) -> Result<SharedObjectToken, BrokerError> {
        self.lock()
            .get(&process)
            .ok_or(BrokerError::UnsupportedOperation)?
            .send(object)
            .map(SharedObjectToken)
            .map_err(|_| BrokerError::ResourceExhausted)
    }
}

/// A natively cloned runner that [`authenticate_clone`] found holding the runner's end of the
/// control connection the broker created for it.
pub(crate) struct AuthenticatedClone {
    process_id: u32,
    connection: ChildConnection,
}

/// Authenticates the natively cloned runner that `runner_descriptor` names as the holder of the
/// runner's end of `connection`, which [`create_child_connection`] created, by the credentials of
/// the first data the clone sends on it by `deadline`.
pub(super) fn authenticate_clone(
    runner_descriptor: Vec<u8>,
    connection: Option<ChildConnection>,
    deadline: Instant,
) -> IoResult<AuthenticatedClone> {
    let descriptor = ExistingRunnerDescriptor::decode(&runner_descriptor)?;
    let mut connection = connection.ok_or_else(|| {
        IoError::new(
            ErrorKind::PermissionDenied,
            "the runner clone has no control connection",
        )
    })?;
    ensure_running_child(descriptor.process_id)?;
    admit_sender_process(&mut connection, descriptor.process_id, deadline)?;
    Ok(AuthenticatedClone {
        process_id: descriptor.process_id,
        connection,
    })
}

/// Checks that `process_id` names a running child of this broker, which keeps the ID from being
/// reused until this broker reaps it.
fn ensure_running_child(process_id: u32) -> IoResult<()> {
    let process_id = libc::id_t::from(process_id);
    // SAFETY: A zeroed siginfo_t is valid output storage for waitid.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    // WNOWAIT observes without reaping, so another child's exit status is never consumed here.
    // SAFETY: `info` is writable, and the call takes no other pointers.
    if unsafe {
        libc::waitid(
            libc::P_PID,
            process_id,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } < 0
    {
        let error = IoError::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ECHILD) {
            IoError::new(
                ErrorKind::PermissionDenied,
                "runner clone is not a child of the broker",
            )
        } else {
            error
        });
    }
    // SAFETY: waitid initialized `info`, whose PID is zero if no child has exited.
    if unsafe { info.si_pid() } != 0 {
        return Err(IoError::new(
            ErrorKind::BrokenPipe,
            "runner clone exited before adoption",
        ));
    }
    Ok(())
}

/// Adopts a natively cloned runner that [`authenticate_clone`] authenticated.
pub(super) fn adopt(
    _parent: &Arc<Mutex<RunnerProcess>>,
    clone: AuthenticatedClone,
    supervised: &SupervisedRunners,
) -> IoResult<(RunnerProcess, PlatformRunnerEndpoint)> {
    let AuthenticatedClone {
        process_id,
        connection,
    } = clone;
    if supervised.contains_key(&process_id) {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "runner process is already supervised",
        ));
    }
    Ok((
        RunnerProcess::Adopted(AdoptedProcess {
            process_id,
            status: None,
        }),
        PlatformRunnerEndpoint {
            socket_path: PathBuf::new(),
            listener: None,
            directory: None,
            connected: Some(connection),
        },
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
    // The broker delivers host objects, such as the control connections of its children's
    // native clones, through its end for as long as it serves the association.
    let registration = launcher
        .shared_object_senders()
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
        // Holding the lock keeps the runner unreaped, so its PID cannot be
        // reused before the pidfd pins the process.
        let pid = libc::pid_t::try_from(runner.id()).map_err(|_| ErrorKind::InvalidInput)?;
        litebox_platform_linux_userland::process::pidfd_open(pid).ok()
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

        let senders = SharedObjectSenders::default();
        let parent = ProcessId(1);
        let (mut broker_end, runner_end) = create_child_connection().unwrap();
        // A process whose runner cannot be sent objects receives none.
        assert_eq!(
            senders.send(parent, runner_end.as_fd()),
            Err(BrokerError::UnsupportedOperation)
        );

        let (sender, runner) = SharedObjectSender::pair().unwrap();
        let channel =
            litebox_platform_linux_userland::shared_objects::SharedObjectChannel::new(runner);
        let registration = senders.register(parent, sender);
        let token = senders.send(parent, runner_end.as_fd()).unwrap();
        drop(runner_end);
        let mut runner_end = UnixStream::from(channel.take(token.0).unwrap());
        runner_end.write_all(b"x").unwrap();
        let mut byte = [0];
        broker_end.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");

        drop(registration);
        assert_eq!(
            senders.send(parent, runner_end.as_fd()),
            Err(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn clones_authenticate_by_sending_once_admitted() {
        use std::io::Write as _;

        let deadline = || Instant::now() + Duration::from_secs(5);
        // A child that, holding the runner's end, sends once admitted.
        let spawn_sender = |runner_end: UnixStream| {
            let input = runner_end.try_clone().unwrap();
            Command::new("sh")
                .args(["-c", "head -c 1 >/dev/null && echo x"])
                .stdin(Stdio::from(OwnedFd::from(input)))
                .stdout(Stdio::from(OwnedFd::from(runner_end)))
                .spawn()
                .unwrap()
        };
        let denied = |result: IoResult<AuthenticatedClone>| {
            result
                .err()
                .expect("the clone must not be authenticated")
                .kind()
        };

        let (broker_end, runner_end) = create_child_connection().unwrap();
        let mut clone = spawn_sender(runner_end);
        let authenticated =
            authenticate_clone(descriptor(clone.id()), Some(broker_end), deadline()).unwrap();
        assert_eq!(authenticated.process_id, clone.id());
        assert!(clone.wait().unwrap().success());

        // Another child, such as one its parent runner forked, sends instead of the named clone.
        let (broker_end, runner_end) = create_child_connection().unwrap();
        let mut sender = spawn_sender(runner_end);
        let mut named = sleeper();
        assert_eq!(
            denied(authenticate_clone(
                descriptor(named.id()),
                Some(broker_end),
                deadline()
            )),
            ErrorKind::PermissionDenied
        );
        assert!(sender.wait().unwrap().success());

        // Data queued before the named child was pinned may come from an earlier holder of its
        // process ID.
        let (broker_end, mut runner_end) = create_child_connection().unwrap();
        runner_end.write_all(b"x").unwrap();
        assert_eq!(
            denied(authenticate_clone(
                descriptor(named.id()),
                Some(broker_end),
                deadline()
            )),
            ErrorKind::PermissionDenied
        );
        named.kill().unwrap();
        named.wait().unwrap();

        // PID 1 is never this broker's child.
        let (broker_end, _runner_end) = create_child_connection().unwrap();
        assert_eq!(
            denied(authenticate_clone(
                descriptor(1),
                Some(broker_end),
                deadline()
            )),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            denied(authenticate_clone(
                descriptor(std::process::id()),
                None,
                deadline()
            )),
            ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn clones_that_exited_or_never_held_the_connection_are_rejected() {
        use std::io::Read as _;

        let denied = |result: IoResult<AuthenticatedClone>| {
            result
                .err()
                .expect("the clone must not be authenticated")
                .kind()
        };

        // A clone that its parent killed stays this broker's unreaped child, so its process ID is
        // never reused, and the clone is rejected as exited.
        let mut killed = sleeper();
        killed.kill().unwrap();
        // SAFETY: A zeroed siginfo_t is valid output storage for waitid.
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: `info` is writable. WNOWAIT waits for the exit without reaping the child.
        let waited = unsafe {
            libc::waitid(
                libc::P_PID,
                killed.id(),
                &raw mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(waited, 0);
        let (broker_end, _runner_end) = create_child_connection().unwrap();
        assert_eq!(
            denied(authenticate_clone(
                descriptor(killed.id()),
                Some(broker_end),
                Instant::now() + Duration::from_secs(5)
            )),
            ErrorKind::BrokenPipe
        );
        killed.wait().unwrap();

        // A live child that never held the connection, such as another runner's clone that took
        // over the process ID of an earlier holder, is admitted on it but never sends there.
        let mut unrelated = sleeper();
        let (broker_end, mut runner_end) = create_child_connection().unwrap();
        assert_eq!(
            denied(authenticate_clone(
                descriptor(unrelated.id()),
                Some(broker_end),
                Instant::now() + Duration::from_millis(50)
            )),
            ErrorKind::TimedOut
        );
        // The admission reached only the connection's holders.
        let mut admission = [0];
        runner_end.read_exact(&mut admission).unwrap();
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
    }

    #[test]
    fn adoption_rejects_supervised_clones() {
        let parent = Arc::new(Mutex::new(RunnerProcess::Spawned(sleeper())));
        let clone = |process_id| AuthenticatedClone {
            process_id,
            connection: UnixStream::pair().unwrap().0,
        };
        let error = adopt(&parent, clone(2), &SupervisedRunners::from([(2, 1)]))
            .err()
            .expect("a supervised runner must not be adopted again");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        let (runner, endpoint) = adopt(&parent, clone(2), &SupervisedRunners::new()).unwrap();
        assert_eq!(runner.id(), 2);
        assert!(endpoint.connected.is_some());
        let RunnerProcess::Spawned(parent) = &mut *parent.lock().unwrap() else {
            unreachable!();
        };
        parent.kill().unwrap();
        parent.wait().unwrap();
    }
}
