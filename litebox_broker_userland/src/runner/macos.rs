// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS runner endpoints.
//!
//! Runners connect over a Unix socket and receive POSIX shared memory. A spawned runner connects
//! to a listener in a private directory, and the broker creates a natively forked runner's
//! control connection before the clone exists, delivering the runner's end over the parent's
//! shared-object channel (see [`deliver_child_connection`]). Process images are unsupported, so a
//! spawned runner always starts from a fresh program.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::process::CpuTime;
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_protocol::{ProcessId, SharedObjectToken};
use litebox_broker_transport_macos_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_broker_transport_macos_userland::shared_memory::MacosSharedMemory;
use litebox_broker_transport_macos_userland::shared_objects::SharedObjectSender;
use litebox_broker_transport_macos_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{
    PendingRunnerAssociation, RUNNER_POLL_INTERVAL, RunnerExit, RunnerKind, RunnerProcess,
    SupervisedRunners, UserlandProcessLauncher, accept_runner_channel, runner_has_exited,
};
use crate::runtime::{AssociationOutcome, is_peer_closed_error};

/// Orders runner spawns against broker descriptor creation. macOS creates
/// sockets and POSIX shared memory without atomic close-on-exec, and `std`'s
/// `posix_spawn` sets no `POSIX_SPAWN_CLOEXEC_DEFAULT`, so any runner spawned
/// between creation and `FD_CLOEXEC` would inherit the descriptor. Inheritance
/// is process-wide, so the fence is too: spawns hold it exclusively and
/// creations hold it shared.
pub(super) static SPAWN_FENCE: RwLock<()> = RwLock::new(());

/// Runs `create`, which makes a descriptor and marks it close-on-exec, with no
/// runner spawn in between.
fn without_concurrent_spawn<T>(create: impl FnOnce() -> T) -> T {
    let _creating = SPAWN_FENCE.read().expect("spawn fence poisoned");
    create()
}

/// Fails: copy-based fork, which starts a runner from its parent's memory image, is
/// deliberately not implemented on macOS for security reasons (it needs runners with weakened
/// protections, such as ASLR disabled). Runners fork natively instead.
pub(crate) fn create_image(_capacity: u64) -> Result<Box<dyn ProcessImage>, BrokerError> {
    Err(BrokerError::UnsupportedOperation)
}

/// Converts a Darwin signal number to the Linux signal number reported to the
/// guest, or `None` for a signal Linux lacks.
pub(super) const fn guest_signal_number(signal: i32) -> Option<u32> {
    Some(match signal {
        libc::SIGHUP => 1,
        libc::SIGINT => 2,
        libc::SIGQUIT => 3,
        libc::SIGILL => 4,
        libc::SIGTRAP => 5,
        libc::SIGABRT => 6,
        libc::SIGBUS => 7,
        libc::SIGFPE => 8,
        libc::SIGKILL => 9,
        libc::SIGUSR1 => 10,
        libc::SIGSEGV => 11,
        libc::SIGUSR2 => 12,
        libc::SIGPIPE => 13,
        libc::SIGALRM => 14,
        libc::SIGTERM => 15,
        libc::SIGCHLD => 17,
        libc::SIGCONT => 18,
        libc::SIGSTOP => 19,
        libc::SIGTSTP => 20,
        libc::SIGTTIN => 21,
        libc::SIGTTOU => 22,
        libc::SIGURG => 23,
        libc::SIGXCPU => 24,
        libc::SIGXFSZ => 25,
        libc::SIGVTALRM => 26,
        libc::SIGPROF => 27,
        libc::SIGWINCH => 28,
        libc::SIGIO => 29,
        libc::SIGSYS => 31,
        _ => return None,
    })
}

/// `audit_token_t` from `<bsm/audit.h>`: a process identity that, unlike a
/// process ID, names one process even after it exits and its ID is reused.
///
/// `litebox_platform_macos_userland::process` declares the same FFI for the
/// runner side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct AuditToken([u32; 8]);

/// `TASK_AUDIT_TOKEN` and `TASK_AUDIT_TOKEN_COUNT` from `<mach/task_info.h>`.
const TASK_AUDIT_TOKEN: libc::task_flavor_t = 15;
const TASK_AUDIT_TOKEN_COUNT: libc::mach_msg_type_number_t = 8;

unsafe extern "C" {
    /// `proc_signal_with_audittoken` from `<libproc.h>`. Returns zero or an
    /// `errno` value, which is `ESRCH` once the process has exited.
    fn proc_signal_with_audittoken(token: *mut AuditToken, signal: libc::c_int) -> libc::c_int;
    /// `task_name_for_pid` from `<mach/mach_traps.h>`. A task name port only
    /// permits inspection, and the kernel grants it for processes of this user.
    fn task_name_for_pid(
        target: libc::mach_port_t,
        process_id: libc::pid_t,
        name: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;
    /// `mach_port_deallocate` from `<mach/mach_port.h>`.
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
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
    /// Binds a nonblocking listener in a new private directory. The caller must hold
    /// [`SPAWN_FENCE`].
    pub(super) fn create() -> IoResult<Self> {
        // `sun_path` holds at most 104 bytes and `$TMPDIR` is long on macOS, so the directory
        // prefix and socket name stay short.
        let directory = tempfile::Builder::new()
            .prefix("litebox-broker-")
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
            // Adoption identified the clone that the broker delivered this stream's peer for.
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

/// A runner natively forked by another runner, which is not this broker's
/// child: the broker can neither reap it nor rely on its process ID staying
/// unused, so it observes the exit through a kqueue and signals by audit token.
///
/// An audit token also changes when its process executes a new program. The
/// exit registration survives that, so [`AdoptedProcess::kill`] re-reads the
/// token while the registration shows the runner is still running.
pub(crate) struct AdoptedProcess {
    process_id: u32,
    /// The token taken at adoption, through which the runner is signaled.
    token: AuditToken,
    /// Holds this runner's one-shot `EVFILT_PROC` exit registration.
    exit_queue: OwnedFd,
    status: Option<ExitStatus>,
}

impl AdoptedProcess {
    /// Starts observing the running process `process_id` and records its
    /// audit token.
    fn watch(process_id: u32) -> IoResult<Self> {
        let pid = libc::pid_t::try_from(process_id).map_err(|_| ErrorKind::InvalidInput)?;
        // SAFETY: `kqueue` takes no arguments.
        let exit_queue = unsafe { libc::kqueue() };
        if exit_queue < 0 {
            return Err(IoError::last_os_error());
        }
        // SAFETY: A successful `kqueue` returns a new descriptor that nothing
        // else owns. Kernel queues are not inherited by child processes.
        let exit_queue = unsafe { OwnedFd::from_raw_fd(exit_queue) };
        let registration = kevent(
            process_id as libc::uintptr_t,
            libc::EVFILT_PROC,
            libc::NOTE_EXIT | libc::NOTE_EXITSTATUS,
        );
        // SAFETY: `exit_queue` is live, `registration` is one valid change
        // entry, and no events are requested. `ESRCH` reports a process that
        // has exited, including an unreaped one.
        if unsafe {
            libc::kevent(
                exit_queue.as_raw_fd(),
                &raw const registration,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(IoError::last_os_error());
        }
        let mut process = Self {
            process_id,
            token: audit_token_of(pid)?,
            exit_queue,
            status: None,
        };
        // The token names whichever process held the ID when it was taken. If
        // the registered process is still running, that is the same process.
        if process.try_wait()?.is_some() {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                "runner exited before adoption",
            ));
        }
        Ok(process)
    }

    pub(super) const fn id(&self) -> u32 {
        self.process_id
    }

    fn try_wait(&mut self) -> IoResult<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let mut event = kevent(0, 0, 0);
        let poll = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `exit_queue` is live, `event` is writable for one entry, and
        // `poll` is a valid timespec for the call.
        let result = unsafe {
            libc::kevent(
                self.exit_queue.as_raw_fd(),
                std::ptr::null(),
                0,
                &raw mut event,
                1,
                &raw const poll,
            )
        };
        if result < 0 {
            let error = IoError::last_os_error();
            return if error.kind() == ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if result == 0 {
            return Ok(None);
        }
        // `NOTE_EXITSTATUS` delivers the `waitpid` status in `data`.
        let status =
            i32::try_from(event.data).map_err(|_| IoError::from(ErrorKind::InvalidData))?;
        let status = ExitStatus::from_raw(status);
        self.status = Some(status);
        Ok(Some(status))
    }

    /// Kills the runner, or succeeds if it has already exited.
    ///
    /// Fails if the runner keeps executing new programs, each of which changes
    /// its token, or becomes uninspectable before it can be signaled.
    pub(super) fn kill(&mut self) -> IoResult<()> {
        /// Bounds the signal attempts, since callers hold the runner's lock.
        const KILL_ATTEMPTS: u32 = 16;
        /// Waits for an exit or a program change in progress to complete.
        const KILL_RETRY_DELAY: Duration = Duration::from_millis(1);
        if self.status.is_some() {
            return Ok(());
        }
        let pid = libc::pid_t::try_from(self.process_id).map_err(|_| ErrorKind::InvalidInput)?;
        let mut token = self.token;
        let mut last_error = None;
        for _ in 0..KILL_ATTEMPTS {
            // SAFETY: `token` is a valid audit token; the kernel rejects it
            // once its process is gone or has executed a new program, so a
            // reused process ID is never signaled.
            match unsafe { proc_signal_with_audittoken(&raw mut token, libc::SIGKILL) } {
                0 => return Ok(()),
                libc::ESRCH => {}
                error => return Err(IoError::from_raw_os_error(error)),
            }
            let current = audit_token_of(pid);
            // While the registered runner has not exited, its process ID is
            // not reused, so a token read before this check is the runner's.
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            match current {
                Ok(current) if current != token => token = current,
                // The runner is exiting or between programs.
                Ok(_) => std::thread::sleep(KILL_RETRY_DELAY),
                Err(error) => {
                    last_error = Some(error);
                    std::thread::sleep(KILL_RETRY_DELAY);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            IoError::other(format!(
                "runner process {} kept changing its audit token while being killed",
                self.process_id
            ))
        }))
    }
}

impl RunnerKind {
    /// Reaps a spawned runner if it exited, or observes an adopted one's exit, returning the
    /// exit.
    ///
    /// An adopted runner is not this broker's child, and its parent may reap it at once, so its
    /// CPU time is unavailable and reported as zero.
    pub(super) fn try_wait(&mut self) -> IoResult<Option<RunnerExit>> {
        match self {
            Self::Spawned(process) => reap_child(process.id()),
            Self::Adopted(process) => Ok(process.try_wait()?.map(|status| RunnerExit {
                status,
                cpu_time: CpuTime::default(),
            })),
        }
    }
}

/// Reaps the broker's child `process_id` if it exited, returning its exit and the CPU time it
/// used.
///
/// The child is reaped here rather than through its `Child`, which cannot report usage; the
/// caller never uses the `Child` to wait for or kill a reaped runner.
fn reap_child(process_id: u32) -> IoResult<Option<RunnerExit>> {
    let process_id = libc::pid_t::try_from(process_id).map_err(|_| ErrorKind::InvalidInput)?;
    let mut status = 0;
    // SAFETY: A zeroed rusage is valid output storage for wait4.
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    // SAFETY: `process_id` names an unreaped direct child of this broker, and `status` and
    // `usage` are writable.
    let result = unsafe { libc::wait4(process_id, &raw mut status, libc::WNOHANG, &raw mut usage) };
    if result < 0 {
        return Err(IoError::last_os_error());
    }
    let duration = |time: libc::timeval| {
        Duration::from_secs(u64::try_from(time.tv_sec).unwrap_or(0))
            + Duration::from_micros(u64::try_from(time.tv_usec).unwrap_or(0))
    };
    Ok((result != 0).then(|| RunnerExit {
        status: ExitStatus::from_raw(status),
        cpu_time: CpuTime {
            user: duration(usage.ru_utime),
            system: duration(usage.ru_stime),
        },
    }))
}

/// Returns whether `error` reports that this process or the system ran out of descriptors.
pub(crate) fn is_out_of_descriptors(error: &IoError) -> bool {
    matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
}

/// The broker's end of a natively forked runner's control connection, which
/// [`deliver_child_connection`] creates before the clone exists, with the broker's copy of the
/// runner's end.
///
/// macOS's collector of in-flight Unix-domain descriptors can destroy a socket that is in flight
/// while no process holds it, so the broker keeps the runner's end until the parent runner has
/// taken it, which it does before forking the clone that [`authenticate_clone`] names.
pub(crate) struct ChildConnection {
    connection: UnixStream,
    runner_end: UnixStream,
}

/// Creates the control connection through which a native clone of `parent`'s runner will
/// associate, and sends the runner's end to that runner, which the clone inherits.
///
/// Returns the broker's end, for [`authenticate_clone`], and the token under which the runner
/// takes its end.
pub(crate) fn deliver_child_connection(
    senders: &SharedObjectSenders,
    parent: ProcessId,
) -> Result<(ChildConnection, SharedObjectToken), BrokerError> {
    let (connection, runner_end) = without_concurrent_spawn(|| {
        let (connection, runner_end) = UnixStream::pair()?;
        set_no_sigpipe(&connection)?;
        set_no_sigpipe(&runner_end)?;
        IoResult::Ok((connection, runner_end))
    })
    .map_err(|error| {
        litebox_util_log::warn!("cannot create a native fork control connection: {error}");
        BrokerError::ResourceExhausted
    })?;
    let token = senders.send(parent, runner_end.as_fd())?;
    Ok((
        ChildConnection {
            connection,
            runner_end,
        },
        token,
    ))
}

/// Makes writes to `stream` whose peer closed fail with `EPIPE` rather than raise `SIGPIPE`.
///
/// macOS has no `MSG_NOSIGNAL`, and `std` sets `SO_NOSIGPIPE` only on connected and accepted
/// sockets, not on socket pairs.
fn set_no_sigpipe(stream: &UnixStream) -> IoResult<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: `stream` is a live socket, and `enabled` is readable for the given length.
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&raw const enabled).cast(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("c_int size fits socklen_t"),
        )
    };
    if result != 0 {
        return Err(IoError::last_os_error());
    }
    Ok(())
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

/// A natively forked runner that [`authenticate_clone`] named, with the control connection the
/// broker created for it.
pub(crate) struct AuthenticatedClone {
    process_id: u32,
    connection: UnixStream,
}

/// Pairs the natively forked runner that `runner_descriptor` names with `connection`, which
/// [`adopt`] then checks the runner for.
///
/// Unlike Linux, macOS cannot attribute data on a socket pair to its sender: `LOCAL_PEERPID` and
/// `LOCAL_PEERTOKEN` report the pair's creator, this broker. The connection is attributed to the
/// clone because the broker delivered its other end only to the parent runner, which hands it to
/// its clone, and [`adopt`] requires the named process to be a running, unsupervised child of
/// that parent. A parent that keeps the end, or hands it to another of its descendants, gains no
/// authority it lacks: they all run in its sandbox.
pub(super) fn authenticate_clone(
    runner_descriptor: Vec<u8>,
    connection: Option<ChildConnection>,
    _deadline: Instant,
) -> IoResult<AuthenticatedClone> {
    let descriptor = ExistingRunnerDescriptor::decode(&runner_descriptor)?;
    let ChildConnection {
        connection,
        runner_end,
    } = connection.ok_or_else(|| {
        IoError::new(
            ErrorKind::PermissionDenied,
            "the runner clone has no control connection",
        )
    })?;
    // The parent took its end before forking the clone, so only the runners keep it now, and
    // the broker sees the end of the stream once the clone exits.
    drop(runner_end);
    Ok(AuthenticatedClone {
        process_id: descriptor.process_id,
        connection,
    })
}

/// Adopts a natively forked runner that [`authenticate_clone`] named, which associates over the
/// connection the broker created for it.
///
/// The clone must be a running child of `parent` that no runner instance supervises
/// (`supervised` holds their host process IDs). It is not this broker's child, so it is observed
/// through a kqueue exit registration and its audit token rather than its process ID.
pub(super) fn adopt(
    parent: &Arc<Mutex<RunnerProcess>>,
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
    let mut runner = AdoptedProcess::watch(process_id)?;
    {
        let mut parent = parent.lock().expect("parent runner process mutex poisoned");
        let parent_process_id = parent.id();
        // While the parent runs, its process ID is not reused, and the clone's
        // parent ID cannot name another process: an orphan's parent is launchd.
        // The parent was running when it requested adoption, so a parent that
        // is still running after the read held its ID throughout.
        let clone_parent_id = parent_process_id_of(process_id)?;
        if parent.try_wait()?.is_some() {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                "parent runner exited during adoption",
            ));
        }
        if clone_parent_id != parent_process_id {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "runner process is not a child of the requesting runner",
            ));
        }
    }
    // A still-running registered clone is the process whose parent was read.
    if runner.try_wait()?.is_some() {
        return Err(IoError::new(
            ErrorKind::BrokenPipe,
            "runner exited before adoption",
        ));
    }
    Ok((
        RunnerProcess::new(RunnerKind::Adopted(runner)),
        PlatformRunnerEndpoint::Connected(connection),
    ))
}

/// Returns the audit token of the process holding `pid`.
fn audit_token_of(pid: libc::pid_t) -> IoResult<AuditToken> {
    // SAFETY: `mach_task_self` reads this process's task port.
    #[expect(deprecated, reason = "libc suggests the mach2 crate, not a dependency")]
    let task = unsafe { libc::mach_task_self() };
    let mut name: libc::mach_port_t = 0;
    // SAFETY: `name` is writable. Mach port rights are not inherited by
    // spawned runners.
    let result = unsafe { task_name_for_pid(task, pid, &raw mut name) };
    if result != libc::KERN_SUCCESS {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            format!("cannot inspect runner process {pid}: kern_return_t {result}"),
        ));
    }
    let mut token = AuditToken([0; 8]);
    let mut count = TASK_AUDIT_TOKEN_COUNT;
    // SAFETY: `name` is a task name port this process owns, and `token` is
    // writable storage of `count` naturals for this flavor.
    let result = unsafe {
        libc::task_info(
            name,
            TASK_AUDIT_TOKEN,
            (&raw mut token).cast(),
            &raw mut count,
        )
    };
    // SAFETY: This releases the send right `task_name_for_pid` created.
    unsafe { mach_port_deallocate(task, name) };
    if result != libc::KERN_SUCCESS {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            format!("cannot identify runner process {pid}: kern_return_t {result}"),
        ));
    }
    Ok(token)
}

/// Returns the parent process ID of the running process `process_id`.
fn parent_process_id_of(process_id: u32) -> IoResult<u32> {
    let pid = libc::pid_t::try_from(process_id).map_err(|_| ErrorKind::InvalidInput)?;
    // SAFETY: An all-zero `proc_bsdinfo` is valid plain data.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>())
        .expect("proc_bsdinfo size fits c_int");
    // SAFETY: `info` is writable for `size` bytes.
    let written =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
    // `proc_pidinfo` writes nothing for a process that has exited.
    if written != size {
        return Err(IoError::new(
            ErrorKind::BrokenPipe,
            format!("cannot read the parent of runner process {process_id}"),
        ));
    }
    Ok(info.pbi_ppid)
}

fn serve_association(
    control_channel: IoResult<UnixStreamHostSetupChannel>,
    runner: &Arc<Mutex<RunnerProcess>>,
    mut startup: PendingRunnerAssociation,
    setup_deadline: Instant,
    broker: BrokerCore,
    launcher: Arc<UserlandProcessLauncher>,
) -> AssociationOutcome {
    if startup.take_image().is_some() {
        return AssociationOutcome {
            result: Err(IoError::new(
                ErrorKind::Unsupported,
                "macOS runners cannot start from a process image",
            )),
            abnormal: true,
        };
    }
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
    let (shared_objects, runner_shared_objects) =
        match without_concurrent_spawn(SharedObjectSender::pair) {
            Ok(pair) => pair,
            Err(error) => {
                return AssociationOutcome {
                    result: Err(error),
                    abnormal: true,
                };
            }
        };
    // Delivery to this runner lasts while the association is served. macOS's collector of
    // in-flight Unix-domain descriptors can destroy a socket that is in flight while no process
    // holds it, so the broker keeps the runner's end for as long, rather than only until it has
    // sent it.
    let registration = launcher
        .shared_object_senders
        .register(startup.process.id(), shared_objects);
    let outcome = crate::runtime::serve_out_of_process_runner_association(
        startup,
        broker,
        control_channel,
        || without_concurrent_spawn(|| MacosSharedMemory::create(SHARED_BUFFER_POOL_SIZE)),
        |layout| without_concurrent_spawn(|| MacosSharedMemory::create_control_ring(layout)),
        |channel, shared_memory, control_memory| {
            channel.send_shared_memory(shared_memory, Some(setup_deadline))?;
            channel.send_shared_memory(control_memory, Some(setup_deadline))?;
            channel.send_shared_object_channel(runner_shared_objects.as_fd(), Some(setup_deadline))
        },
        UnixStreamHostSetupChannel::into_active,
        Arc::clone(&launcher),
    );
    drop(registration);
    drop(runner_shared_objects);
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
        || without_concurrent_spawn(|| control_listener.accept()).map(|(stream, _)| stream),
        |remaining| wait_for_runner_event(runner, Some(control_listener), Some(remaining)),
    )?;
    // macOS accepted sockets inherit the listener's `O_NONBLOCK`, but setup
    // I/O relies on blocking reads with timeouts.
    control_stream.set_nonblocking(false)?;
    {
        let mut runner = runner.lock().expect("runner process mutex poisoned");
        if runner.try_wait()?.is_some() {
            return Err(IoError::new(
                ErrorKind::BrokenPipe,
                "runner exited before peer authentication",
            ));
        }
        // Only spawned runners listen, and an unreaped child's process ID cannot be reused.
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
    // SAFETY: `kqueue` takes no arguments.
    let kqueue = unsafe { libc::kqueue() };
    if kqueue < 0 {
        // Without a kqueue, fall back to polling for exit and connections.
        std::thread::sleep(timeout.map_or(RUNNER_POLL_INTERVAL, |t| t.min(RUNNER_POLL_INTERVAL)));
        return Ok(());
    }
    // SAFETY: A successful `kqueue` returns a new descriptor that nothing else
    // owns. Kernel queues are not inherited by child processes.
    let kqueue = unsafe { OwnedFd::from_raw_fd(kqueue) };
    let mut changes = Vec::with_capacity(2);
    {
        let mut runner = runner.lock().expect("runner process mutex poisoned");
        if runner.try_wait()?.is_some() {
            return Ok(());
        }
        // The registration pins whichever process holds the runner's ID. That
        // is the runner if it is still running afterwards, as rechecked below:
        // holding the lock keeps a spawned runner unreaped, but an adopted
        // runner's parent may reap it.
        changes.push(kevent(
            runner.id() as libc::uintptr_t,
            libc::EVFILT_PROC,
            libc::NOTE_EXIT,
        ));
        if let Some(listener) = listener {
            let listener = libc::uintptr_t::try_from(listener.as_raw_fd())
                .map_err(|_| ErrorKind::InvalidInput)?;
            changes.push(kevent(listener, libc::EVFILT_READ, 0));
        }
        for change in &changes {
            // SAFETY: `kqueue` is live, `change` is one valid change entry,
            // and no events are requested.
            let result = unsafe {
                libc::kevent(
                    kqueue.as_raw_fd(),
                    change,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            };
            if result < 0 {
                let error = IoError::last_os_error();
                // `ESRCH` means the runner already exited and awaits reaping.
                return match error.raw_os_error() {
                    Some(libc::ESRCH | libc::EINTR) => Ok(()),
                    _ => Err(error),
                };
            }
        }
        if runner.try_wait()?.is_some() {
            return Ok(());
        }
    }
    let timeout = timeout.map(|timeout| libc::timespec {
        tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
    });
    let mut event = kevent(0, 0, 0);
    // SAFETY: `kqueue` is live, `event` is writable for one entry, and
    // `timeout` is either null or a valid timespec for the call.
    let result = unsafe {
        libc::kevent(
            kqueue.as_raw_fd(),
            std::ptr::null(),
            0,
            &raw mut event,
            1,
            timeout
                .as_ref()
                .map_or(std::ptr::null(), std::ptr::from_ref),
        )
    };
    if result < 0 {
        let error = IoError::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

/// Returns a one-shot kqueue registration of `filter` on `ident`.
const fn kevent(ident: libc::uintptr_t, filter: i16, fflags: u32) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::wait_for_runner_exit;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::process::{Command, Stdio};

    /// Starts a shell, standing in for a parent runner, that runs `script` in
    /// a forked child and waits for it. Returns the shell and the child's ID.
    ///
    /// `script` reads the shell's standard input, which the test writes, from
    /// descriptor 3.
    fn parent_with_clone(script: &str) -> (Arc<Mutex<RunnerProcess>>, u32) {
        // The clone's descendants may outlive it, so they get no test output.
        let mut parent = Command::new("sh")
            .args([
                "-c",
                &format!("exec 3<&0; ({script}) >/dev/null 2>&1 & echo $!; wait"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut clone_id = String::new();
        BufReader::new(parent.stdout.take().unwrap())
            .read_line(&mut clone_id)
            .unwrap();
        (
            Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Spawned(parent)))),
            clone_id.trim().parse().unwrap(),
        )
    }

    /// Kills `clone_id`, a child of `parent`, and waits for both.
    fn stop(parent: &Arc<Mutex<RunnerProcess>>, clone_id: u32) {
        // SAFETY: `kill` takes no pointers. The clone stays unreaped, so its ID
        // unused by others, until `parent` waits for it after it exits.
        unsafe { libc::kill(clone_id.cast_signed(), libc::SIGKILL) };
        wait_for_runner_exit(parent).unwrap();
    }

    fn descriptor(process_id: u32) -> Vec<u8> {
        ExistingRunnerDescriptor { process_id }.encode().unwrap()
    }

    /// Returns a clone named `process_id` with a control connection.
    fn clone(process_id: u32) -> AuthenticatedClone {
        AuthenticatedClone {
            process_id,
            connection: UnixStream::pair().unwrap().0,
        }
    }

    #[cfg(target_arch = "aarch64")]
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
            litebox_platform_macos_userland::shared_objects::SharedObjectChannel::new(runner);
        let registration = senders.register(parent, sender);
        let (connection, token) = deliver_child_connection(&senders, parent).unwrap();
        let mut broker_end = connection.connection;
        let mut runner_end = UnixStream::from(channel.take(token.0).unwrap());
        // The runner's end carries what its holder sends to the broker's end.
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
    fn clones_are_authenticated_only_with_a_control_connection() {
        let connection = || {
            let (connection, runner_end) = UnixStream::pair().unwrap();
            Some(ChildConnection {
                connection,
                runner_end,
            })
        };
        let clone = authenticate_clone(descriptor(42), connection(), Instant::now()).unwrap();
        assert_eq!(clone.process_id, 42);
        // A clone without a control connection has nothing to associate on.
        assert_eq!(
            authenticate_clone(descriptor(42), None, Instant::now())
                .err()
                .unwrap()
                .kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            authenticate_clone(vec![0; 3], connection(), Instant::now())
                .err()
                .unwrap()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn adoption_requires_an_unsupervised_child_of_the_parent() {
        let (parent, clone_id) = parent_with_clone("exec sleep 30");
        let (other_parent, other_clone_id) = parent_with_clone("exec sleep 30");
        let parent_id = parent.lock().unwrap().id();
        let error = adopt(
            &parent,
            clone(clone_id),
            &SupervisedRunners::from([(clone_id, 1)]),
        )
        .err()
        .expect("a supervised runner must not be adopted again");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        for foreign in [other_clone_id, parent_id] {
            let error = adopt(&parent, clone(foreign), &SupervisedRunners::new())
                .err()
                .expect("a process that is not the parent's child must not be adopted");
            assert_eq!(error.kind(), ErrorKind::PermissionDenied, "pid {foreign}");
        }
        stop(&parent, clone_id);
        stop(&other_parent, other_clone_id);
    }

    #[test]
    fn adopted_runner_is_connected_and_killed_by_its_token() {
        let (parent, clone_id) = parent_with_clone("while :; do sleep 1; done");
        let (runner, endpoint) =
            adopt(&parent, clone(clone_id), &SupervisedRunners::new()).unwrap();
        assert_eq!(runner.id(), clone_id);
        assert!(matches!(endpoint, PlatformRunnerEndpoint::Connected(_)));
        assert!(endpoint.control_channel().is_empty());
        let runner = Arc::new(Mutex::new(runner));

        let killer = {
            let runner = Arc::clone(&runner);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                runner.lock().unwrap().kill().unwrap();
            })
        };
        let started = Instant::now();
        wait_for_runner_event(&runner, None, Some(Duration::from_secs(30))).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the clone's exit must end the wait"
        );
        killer.join().unwrap();
        let exit = wait_for_runner_exit(&runner).unwrap();
        assert_eq!(exit.status.signal(), Some(libc::SIGKILL));
        wait_for_runner_exit(&parent).unwrap();
    }

    #[test]
    fn adopted_runner_reports_its_exit_status_and_outlives_its_reaping() {
        let (parent, clone_id) = parent_with_clone("sleep 0.5; exit 7");
        let mut clone = AdoptedProcess::watch(clone_id).unwrap();
        let mut unobserved = AdoptedProcess::watch(clone_id).unwrap();
        assert!(clone.try_wait().unwrap().is_none());
        let clone = Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Adopted(clone))));
        let exit = wait_for_runner_exit(&clone).unwrap();
        assert_eq!(exit.status.code(), Some(7));
        // The shell reaps the clone, freeing its process ID.
        wait_for_runner_exit(&parent).unwrap();
        unobserved
            .kill()
            .expect("killing a reaped runner by token must succeed without effect");
        assert!(AdoptedProcess::watch(clone_id).is_err());
    }

    #[test]
    fn adopted_runner_is_killed_after_executing_a_new_program() {
        // Once released, the clone executes `cat`, which also ends when a
        // failing test drops `parent` and so closes its input.
        let (parent, clone_id) = parent_with_clone("read -r line <&3 && exec cat <&3");
        let mut clone = AdoptedProcess::watch(clone_id).unwrap();
        let adopted_token = clone.token;
        {
            let RunnerKind::Spawned(shell) = &mut parent.lock().unwrap().kind else {
                unreachable!();
            };
            shell.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
        }
        let pid = libc::pid_t::try_from(clone_id).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while audit_token_of(pid).unwrap() == adopted_token {
            assert!(Instant::now() < deadline, "the clone never executed cat");
            std::thread::sleep(Duration::from_millis(10));
        }
        clone.kill().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = clone.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "killing must end the clone after it executes a new program"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        wait_for_runner_exit(&parent).unwrap();
    }

    #[test]
    fn runner_event_wait_returns_on_exit_and_connection() {
        let runner = Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Spawned(
            Command::new("sh")
                .args(["-c", "sleep 0.2"])
                .spawn()
                .unwrap(),
        ))));
        let started = Instant::now();
        wait_for_runner_event(&runner, None, Some(Duration::from_secs(10))).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must end when the runner exits"
        );
        assert!(runner_has_exited(&runner).unwrap());
        // A reaped runner returns at once.
        wait_for_runner_event(&runner, None, None).unwrap();

        let sleeper = Arc::new(Mutex::new(RunnerProcess::new(RunnerKind::Spawned(
            Command::new("sleep")
                .arg("30")
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        ))));
        let endpoint = without_concurrent_spawn(PlatformRunnerEndpoint::create).unwrap();
        let PlatformRunnerEndpoint::Listening { listener, .. } = &endpoint else {
            unreachable!();
        };
        let started = Instant::now();
        wait_for_runner_event(&sleeper, Some(listener), Some(Duration::from_millis(50))).unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(25),
            "the wait must block while nothing happens"
        );
        let _client = std::os::unix::net::UnixStream::connect(endpoint.control_channel()).unwrap();
        let started = Instant::now();
        wait_for_runner_event(&sleeper, Some(listener), Some(Duration::from_secs(10))).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must end when a runner connects"
        );
        sleeper.lock().unwrap().kill().unwrap();
        wait_for_runner_exit(&sleeper).unwrap();
    }

    #[test]
    fn darwin_signals_are_reported_with_linux_numbers() {
        assert_eq!(guest_signal_number(libc::SIGKILL), Some(9));
        assert_eq!(guest_signal_number(libc::SIGBUS), Some(7));
        assert_eq!(guest_signal_number(libc::SIGUSR1), Some(10));
        assert_eq!(guest_signal_number(libc::SIGSYS), Some(31));
        assert_eq!(guest_signal_number(libc::SIGCHLD), Some(17));
        assert_eq!(guest_signal_number(libc::SIGEMT), None);
        assert_eq!(guest_signal_number(libc::SIGINFO), None);
    }
}
