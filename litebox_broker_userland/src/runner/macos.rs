// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS runner endpoints.
//!
//! Runners connect over a Unix socket and receive POSIX shared memory. Process
//! images and native fork adoption are unsupported, so every runner is started
//! by this broker from a fresh program.

use std::ffi::OsStr;
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use litebox_broker_core::{BrokerCore, BrokerError, ProcessImage};
use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
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

/// Fails: macOS runners cannot start from a parent's memory image.
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

pub(super) struct PlatformRunnerEndpoint {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
    directory: Option<tempfile::TempDir>,
}

impl PlatformRunnerEndpoint {
    pub(super) fn create() -> IoResult<Self> {
        // `sun_path` holds at most 104 bytes and `$TMPDIR` is long on macOS,
        // so the directory prefix and socket name stay short.
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
        let control_channel = match accept_control_channel(
            self.listener
                .as_ref()
                .expect("a live runner instance must own its control listener"),
            runner,
            setup_deadline,
        ) {
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

    pub(super) fn close(&mut self) {
        self.listener.take();
        self.directory.take();
    }
}

/// A natively forked runner, which macOS never adopts.
pub(crate) enum AdoptedProcess {}

impl AdoptedProcess {
    pub(super) const fn id(&self) -> u32 {
        match *self {}
    }

    pub(super) const fn try_wait(&self) -> IoResult<Option<ExitStatus>> {
        match *self {}
    }

    pub(super) const fn kill(&self) -> IoResult<()> {
        match *self {}
    }
}

/// Rejects native fork adoption, which macOS runners do not support.
pub(super) fn adopt(
    _parent: &Arc<Mutex<RunnerProcess>>,
    _runner_descriptor: &[u8],
    _supervised: &SupervisedRunners,
) -> IoResult<(RunnerProcess, PlatformRunnerEndpoint)> {
    Err(IoError::new(
        ErrorKind::Unsupported,
        "macOS runners cannot be adopted after a native fork",
    ))
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
        // Holding the lock keeps the runner unreaped, so its PID cannot be
        // reused before the registration below pins the process.
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
    use std::process::{Command, Stdio};

    #[test]
    fn adoption_is_rejected() {
        let parent = Arc::new(Mutex::new(RunnerProcess::Spawned(
            Command::new("true").spawn().unwrap(),
        )));
        let error = adopt(&parent, &[], &SupervisedRunners::new())
            .err()
            .expect("macOS must not adopt natively forked runners");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
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
        let endpoint = PlatformRunnerEndpoint::create().unwrap();
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
