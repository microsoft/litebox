// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::any::Any;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::ops::Range;
use std::os::fd::{AsFd as _, AsRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ChildConnection, ProcessImage};
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_linux_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_broker_transport_linux_userland::memfd::{MemfdProcessImage, MemfdSharedMemory};
use litebox_broker_transport_linux_userland::shared_objects::SharedObjectSender;
use litebox_broker_transport_linux_userland::unix_socket::{
    UnixStreamHostSetupChannel, enable_sender_credentials, validate_peer_process,
    validate_sender_process,
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

/// The shared-object sender of each association the broker serves, through which it delivers
/// host objects, such as the control connections of its children's native clones, to the
/// association's runner.
#[derive(Default)]
pub(crate) struct SharedObjectSenders(Mutex<HashMap<ProcessId, SharedObjectSender>>);

impl SharedObjectSenders {
    /// Delivers objects to `process`'s runner through `sender` until [`Self::unregister`].
    pub(crate) fn register(&self, process: ProcessId, sender: SharedObjectSender) {
        self.0
            .lock()
            .expect("shared-object senders mutex poisoned")
            .insert(process, sender);
    }

    /// Stops delivering objects to `process`'s runner.
    pub(crate) fn unregister(&self, process: ProcessId) {
        self.0
            .lock()
            .expect("shared-object senders mutex poisoned")
            .remove(&process);
    }

    /// Creates the control connection through which a native clone of `parent`'s runner will
    /// associate, and delivers the runner's end to `parent`'s runner, whose clone inherits it.
    ///
    /// Returns the broker's end, which records the credentials of whoever sends on it, for
    /// [`authenticate_clone`], and the token under which `parent`'s runner takes its end.
    pub(crate) fn create_child_connection(
        &self,
        parent: ProcessId,
    ) -> Result<(UnixStream, u64), BrokerError> {
        let senders = self.0.lock().expect("shared-object senders mutex poisoned");
        let sender = senders
            .get(&parent)
            .ok_or(BrokerError::UnsupportedOperation)?;
        let (broker_end, runner_end) =
            UnixStream::pair().map_err(|_| BrokerError::ResourceExhausted)?;
        enable_sender_credentials(&broker_end).map_err(|_| BrokerError::ResourceExhausted)?;
        let token = sender
            .send(runner_end.as_fd())
            .map_err(|_| BrokerError::ResourceExhausted)?;
        Ok((broker_end, token))
    }
}

/// Checks that the natively cloned runner that `runner_descriptor` names holds the runner's end
/// of `connection`, which [`SharedObjectSenders::create_child_connection`] created, from the
/// credentials of the first data the clone sends on it by `deadline`.
///
/// Its parent's runner can name any process, and delivered the runner's end to whichever
/// process it chose; only the sender's credentials, which the kernel attaches, bind the two.
pub(super) fn authenticate_clone(
    runner_descriptor: &[u8],
    connection: Option<&ChildConnection>,
    deadline: Instant,
) -> IoResult<()> {
    let descriptor = ExistingRunnerDescriptor::decode(runner_descriptor)?;
    let stream = connection
        .and_then(|connection| connection.downcast_ref::<UnixStream>())
        .ok_or_else(missing_connection)?;
    validate_sender_process(stream, descriptor.process_id, deadline)
}

fn missing_connection() -> IoError {
    IoError::new(
        ErrorKind::PermissionDenied,
        "the runner clone has no control connection",
    )
}

/// Adopts a natively cloned runner, which inherited the runner's end of `connection` from its
/// parent, and which [`authenticate_clone`] bound to it.
///
/// The clone must be a running child of this broker that no runner instance supervises
/// (`supervised` holds their host process IDs).
pub(super) fn adopt(
    _parent: &Arc<Mutex<RunnerProcess>>,
    runner_descriptor: &[u8],
    supervised: &SupervisedRunners,
    connection: Option<ChildConnection>,
) -> IoResult<(RunnerProcess, PlatformRunnerEndpoint)> {
    let descriptor = ExistingRunnerDescriptor::decode(runner_descriptor)?;
    if supervised.contains_key(&descriptor.process_id) {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "runner process is already supervised",
        ));
    }
    // SAFETY: A zeroed siginfo_t is valid output storage for waitid.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    // WNOWAIT observes without reaping, so another child's exit status is never consumed here.
    // SAFETY: `info` is writable, and the call takes no other pointers.
    if unsafe {
        libc::waitid(
            libc::P_PID,
            descriptor.process_id,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } < 0
    {
        return Err(IoError::last_os_error());
    }
    // SAFETY: waitid initialized `info`, whose PID is zero if no child has exited.
    if unsafe { info.si_pid() } != 0 {
        return Err(IoError::new(
            ErrorKind::BrokenPipe,
            "runner clone exited before adoption",
        ));
    }
    let stream = connection
        .and_then(|connection| connection.downcast::<UnixStream>().ok())
        .map(|stream| *stream)
        .ok_or_else(missing_connection)?;
    Ok((
        RunnerProcess::Adopted(AdoptedProcess {
            process_id: descriptor.process_id,
            status: None,
        }),
        PlatformRunnerEndpoint {
            socket_path: PathBuf::new(),
            listener: None,
            directory: None,
            connected: Some(stream),
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
    let process_id = startup.process.id();
    launcher
        .shared_object_senders()
        .register(process_id, shared_objects);
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
    launcher.shared_object_senders().unregister(process_id);
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
    // Without a pidfd (kernels before 5.3), fall back to polling for exit.
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
        // A process whose runner cannot be sent objects has no child connections.
        assert_eq!(
            senders.create_child_connection(parent).err(),
            Some(BrokerError::UnsupportedOperation)
        );

        let (sender, runner) = SharedObjectSender::pair().unwrap();
        let channel =
            litebox_platform_linux_userland::shared_objects::SharedObjectChannel::new(runner);
        senders.register(parent, sender);
        let (mut broker_end, token) = senders.create_child_connection(parent).unwrap();
        let mut runner_end = UnixStream::from(channel.take(token).unwrap());
        runner_end.write_all(b"x").unwrap();
        // The broker's end identifies whoever sends on it.
        validate_sender_process(
            &broker_end,
            std::process::id(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let mut byte = [0];
        broker_end.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");

        senders.unregister(parent);
        assert_eq!(
            senders.create_child_connection(parent).err(),
            Some(BrokerError::UnsupportedOperation)
        );
    }

    #[test]
    fn clones_authenticate_by_sending_on_their_connection() {
        let deadline = || Instant::now() + Duration::from_secs(5);
        let connection = |send: bool| {
            let (broker_end, mut runner_end) = UnixStream::pair().unwrap();
            enable_sender_credentials(&broker_end).unwrap();
            if send {
                std::io::Write::write_all(&mut runner_end, b"x").unwrap();
            }
            (Box::new(broker_end) as ChildConnection, runner_end)
        };
        let this_process = descriptor(std::process::id());

        let (sent, _runner_end) = connection(true);
        authenticate_clone(&this_process, Some(&sent), deadline()).unwrap();
        // Another process did not send on it.
        let (sent, _runner_end) = connection(true);
        let other_process = descriptor(std::process::id().checked_add(1).unwrap());
        assert_eq!(
            authenticate_clone(&other_process, Some(&sent), deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::PermissionDenied
        );
        // A clone that never sends is not authenticated.
        let (silent, runner_end) = connection(false);
        drop(runner_end);
        assert!(authenticate_clone(&this_process, Some(&silent), deadline()).is_err());
        for connection in [None, Some(Box::new(0u32) as ChildConnection)] {
            assert_eq!(
                authenticate_clone(&this_process, connection.as_ref(), deadline())
                    .unwrap_err()
                    .kind(),
                ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn adoption_rejects_supervised_and_foreign_processes() {
        let parent = Arc::new(Mutex::new(RunnerProcess::Spawned(sleeper())));
        let parent_id = parent.lock().unwrap().id();
        let connection = || Some(Box::new(UnixStream::pair().unwrap().0) as ChildConnection);
        let error = adopt(
            &parent,
            &descriptor(parent_id),
            &SupervisedRunners::from([(parent_id, 1)]),
            connection(),
        )
        .err()
        .expect("a supervised runner must not be adopted again");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        // PID 1 is never this broker's child.
        assert!(
            adopt(
                &parent,
                &descriptor(1),
                &SupervisedRunners::new(),
                connection()
            )
            .is_err()
        );
        // A clone needs the connection the broker created for it.
        let error = adopt(
            &parent,
            &descriptor(parent_id),
            &SupervisedRunners::new(),
            None,
        )
        .err()
        .expect("a clone without a connection must not be adopted");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        let RunnerProcess::Spawned(parent) = &mut *parent.lock().unwrap() else {
            unreachable!();
        };
        parent.kill().unwrap();
        parent.wait().unwrap();
    }
}
