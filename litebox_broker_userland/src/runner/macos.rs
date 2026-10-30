// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS runner endpoints.
//!
//! Runners connect over a Unix socket and receive POSIX shared memory. Every
//! runner socket lives in one broker-lifetime [`RunnerDirectory`]: the
//! broker's spawned runners connect to `runner-<n>.sock`, and a runner
//! natively forked by another runner connects to the rendezvous socket the
//! broker binds for it on adoption (see
//! [`ExistingRunnerDescriptor::rendezvous_socket_path`]). Process images are
//! unsupported, so a spawned runner always starts from a fresh program.

use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport_macos_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_broker_transport_macos_userland::shared_memory::MacosSharedMemory;
use litebox_broker_transport_macos_userland::unix_socket::{
    UnixStreamHostSetupChannel, validate_peer_process,
};

use super::{
    PendingRunnerAssociation, RUNNER_POLL_INTERVAL, RunnerProcess, SupervisedRunners,
    UserlandProcessLauncher, accept_runner_channel, runner_has_exited,
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

/// The broker-lifetime directory holding every runner's control socket.
///
/// Runners find it as the directory of their `--broker-control-channel` path,
/// and a natively forked runner inherits that path, so the directory must
/// outlive every runner: the process launcher owns it.
pub(crate) struct RunnerDirectory {
    directory: tempfile::TempDir,
    next_runner: AtomicU64,
}

impl RunnerDirectory {
    pub(crate) fn create() -> IoResult<Self> {
        // `sun_path` holds at most 104 bytes and `$TMPDIR` is long on macOS,
        // so the directory prefix and socket names stay short.
        let directory = tempfile::Builder::new()
            .prefix("litebox-broker-")
            .tempdir()?;
        Ok(Self {
            directory,
            next_runner: AtomicU64::new(0),
        })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }
}

pub(super) struct PlatformRunnerEndpoint {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
}

impl PlatformRunnerEndpoint {
    pub(super) fn create(directory: &RunnerDirectory) -> IoResult<Self> {
        let runner = directory.next_runner.fetch_add(1, Ordering::Relaxed);
        Self::listen(directory.path().join(format!("runner-{runner}.sock")))
    }

    /// Binds a nonblocking listener at `socket_path`, which must be inside the
    /// broker-owned runner directory. The caller must hold [`SPAWN_FENCE`].
    fn listen(socket_path: PathBuf) -> IoResult<Self> {
        // A later clone can reuse an adopted runner's process ID, and so its
        // rendezvous path. Every endpoint unlinks its socket on close, so a
        // file still there is stale.
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            socket_path,
            listener: Some(listener),
        })
    }

    pub(super) fn control_channel(&self) -> &OsStr {
        self.socket_path.as_os_str()
    }

    pub(super) fn serve(
        &mut self,
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
        let control_channel = accept_control_channel(
            self.listener
                .as_ref()
                .expect("a live runner instance must own its control listener"),
            runner,
            setup_deadline,
        );
        // Each runner connects once, so its socket is no longer needed.
        self.close();
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
        crate::runtime::serve_out_of_process_runner_association(
            startup,
            broker,
            control_channel,
            || without_concurrent_spawn(|| MacosSharedMemory::create(SHARED_BUFFER_POOL_SIZE)),
            |layout| without_concurrent_spawn(|| MacosSharedMemory::create_control_ring(layout)),
            move |channel, shared_memory, control_memory| {
                channel.send_shared_memory(shared_memory, Some(setup_deadline))?;
                channel.send_shared_memory(control_memory, Some(setup_deadline))
            },
            UnixStreamHostSetupChannel::into_active,
            launcher,
        )
    }

    /// Stops listening and unlinks the socket, so the runner directory holds
    /// only sockets that runners may still connect to.
    pub(super) fn close(&mut self) {
        if self.listener.take().is_some() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
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
    /// The token taken at adoption, which the runner must connect with.
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

    pub(super) fn try_wait(&mut self) -> IoResult<Option<ExitStatus>> {
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

    /// Fails unless the peer of `stream` is this runner.
    fn validate_peer(&self, stream: &UnixStream) -> IoResult<()> {
        let mut token = AuditToken([0; 8]);
        let expected_length = size_of::<AuditToken>();
        let mut actual_length =
            libc::socklen_t::try_from(expected_length).expect("audit token size fits socklen_t");
        // SAFETY: `stream` supplies a live socket descriptor, `token` is
        // writable for `actual_length` bytes, and `actual_length` is a valid
        // writable socklen_t.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                (&raw mut token).cast(),
                &raw mut actual_length,
            )
        };
        if result != 0 {
            return Err(IoError::last_os_error());
        }
        if actual_length as usize != expected_length || token != self.token {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "Unix socket peer is not the adopted runner",
            ));
        }
        Ok(())
    }
}

/// Adopts a runner natively forked by `parent` and binds the rendezvous socket
/// the clone connects to.
///
/// The clone must be a running child of `parent` that no runner instance
/// supervises (`supervised` holds their host process IDs). Its rendezvous path
/// is derived from the validated process ID inside `directory`, which only
/// this broker's user can write to.
pub(super) fn adopt(
    parent: &Arc<Mutex<RunnerProcess>>,
    runner_descriptor: &[u8],
    supervised: &SupervisedRunners,
    directory: &RunnerDirectory,
) -> IoResult<(RunnerProcess, PlatformRunnerEndpoint)> {
    let descriptor = ExistingRunnerDescriptor::decode(runner_descriptor)?;
    if supervised.contains_key(&descriptor.process_id) {
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            "runner process is already supervised",
        ));
    }
    let mut clone = AdoptedProcess::watch(descriptor.process_id)?;
    {
        let mut parent = parent.lock().expect("parent runner process mutex poisoned");
        let parent_process_id = parent.id();
        // While the parent runs, its process ID is not reused, and the clone's
        // parent ID cannot name another process: an orphan's parent is launchd.
        // The parent was running when it requested adoption, so a parent that
        // is still running after the read held its ID throughout.
        let clone_parent_id = parent_process_id_of(descriptor.process_id)?;
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
    if clone.try_wait()?.is_some() {
        return Err(IoError::new(
            ErrorKind::BrokenPipe,
            "runner exited before adoption",
        ));
    }
    let endpoint = without_concurrent_spawn(|| {
        PlatformRunnerEndpoint::listen(descriptor.rendezvous_socket_path(directory.path()))
    })?;
    Ok((RunnerProcess::Adopted(clone), endpoint))
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
        match &*runner {
            // An unreaped child's process ID cannot be reused.
            RunnerProcess::Spawned(child) => validate_peer_process(&control_stream, child.id())?,
            // A clone that is not this broker's child is matched by audit
            // token, which a process reusing its ID cannot present.
            RunnerProcess::Adopted(clone) => clone.validate_peer(&control_stream)?,
        }
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
            Arc::new(Mutex::new(RunnerProcess::Spawned(parent))),
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

    #[test]
    fn adoption_requires_an_unsupervised_child_of_the_parent() {
        let directory = RunnerDirectory::create().unwrap();
        let (parent, clone_id) = parent_with_clone("exec sleep 30");
        let (other_parent, other_clone_id) = parent_with_clone("exec sleep 30");
        let parent_id = parent.lock().unwrap().id();
        let error = adopt(
            &parent,
            &descriptor(clone_id),
            &SupervisedRunners::from([(clone_id, 1)]),
            &directory,
        )
        .err()
        .expect("a supervised runner must not be adopted again");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        for foreign in [other_clone_id, parent_id] {
            let error = adopt(
                &parent,
                &descriptor(foreign),
                &SupervisedRunners::new(),
                &directory,
            )
            .err()
            .expect("a process that is not the parent's child must not be adopted");
            assert_eq!(error.kind(), ErrorKind::PermissionDenied, "pid {foreign}");
        }
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .next()
                .is_none(),
            "a rejected adoption must not bind a rendezvous socket"
        );
        stop(&parent, clone_id);
        stop(&other_parent, other_clone_id);
    }

    #[test]
    fn adopted_runner_is_authenticated_by_token_and_killed_by_it() {
        let directory = RunnerDirectory::create().unwrap();
        let (parent, clone_id) = parent_with_clone("while :; do sleep 1; done");
        let (runner, mut endpoint) = adopt(
            &parent,
            &descriptor(clone_id),
            &SupervisedRunners::new(),
            &directory,
        )
        .unwrap();
        let rendezvous = ExistingRunnerDescriptor {
            process_id: clone_id,
        }
        .rendezvous_socket_path(directory.path());
        assert_eq!(endpoint.control_channel(), rendezvous.as_os_str());
        let runner = Arc::new(Mutex::new(runner));
        let listener = endpoint.listener.as_ref().unwrap();

        let _impostor = UnixStream::connect(&rendezvous).unwrap();
        let error =
            accept_control_channel(listener, &runner, Instant::now() + Duration::from_secs(30))
                .err()
                .expect("only the adopted runner may connect");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);

        let killer = {
            let runner = Arc::clone(&runner);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                runner.lock().unwrap().kill().unwrap();
            })
        };
        let started = Instant::now();
        let error =
            accept_control_channel(listener, &runner, Instant::now() + Duration::from_secs(30))
                .err()
                .expect("a runner that exits never connects");
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the clone's exit must end the accept wait"
        );
        killer.join().unwrap();
        let status = wait_for_runner_exit(&runner).unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));

        endpoint.close();
        assert!(!rendezvous.exists(), "closing must unlink the rendezvous");
        wait_for_runner_exit(&parent).unwrap();
    }

    #[test]
    fn adopted_runner_reports_its_exit_status_and_outlives_its_reaping() {
        let (parent, clone_id) = parent_with_clone("sleep 0.5; exit 7");
        let mut clone = AdoptedProcess::watch(clone_id).unwrap();
        let mut unobserved = AdoptedProcess::watch(clone_id).unwrap();
        assert!(clone.try_wait().unwrap().is_none());
        let clone = Arc::new(Mutex::new(RunnerProcess::Adopted(clone)));
        let status = wait_for_runner_exit(&clone).unwrap();
        assert_eq!(status.code(), Some(7));
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
            let RunnerProcess::Spawned(shell) = &mut *parent.lock().unwrap() else {
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
        let runner = Arc::new(Mutex::new(RunnerProcess::Spawned(
            Command::new("sh")
                .args(["-c", "sleep 0.2"])
                .spawn()
                .unwrap(),
        )));
        let started = Instant::now();
        wait_for_runner_event(&runner, None, Some(Duration::from_secs(10))).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait must end when the runner exits"
        );
        assert!(runner_has_exited(&runner).unwrap());
        // A reaped runner returns at once.
        wait_for_runner_event(&runner, None, None).unwrap();

        let sleeper = Arc::new(Mutex::new(RunnerProcess::Spawned(
            Command::new("sleep")
                .arg("30")
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        )));
        let directory = RunnerDirectory::create().unwrap();
        let endpoint = PlatformRunnerEndpoint::create(&directory).unwrap();
        let listener = endpoint.listener.as_ref().unwrap();
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
        let RunnerProcess::Spawned(sleeper) = &mut *sleeper.lock().unwrap() else {
            unreachable!();
        };
        sleeper.kill().unwrap();
        sleeper.wait().unwrap();
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
