// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner processes: one per guest process, each this binary in [`RUNNER_MODE`], which calls the
//! unchanged Linux runner library against the container's broker in the daemon.
//!
//! Runners are spawned from one thread that outlives them, since Linux sends the parent-death
//! signal when the spawning thread exits: the thread ends only with [`Runners`], which every
//! [`Runner`] holds until it reaped its runner. Each runner has exactly one owner, its
//! [`Runner`], which accepts its connection and reaps it; everyone else signals it only through
//! its pidfd, which cannot name a reused process ID. Every runner is registered from its spawn
//! until it is reaped, under the lock that also holds the container's `closed` flag, so closing
//! the container reaches every runner that will ever exist.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use litebox_broker_protocol::ProcessId;
use litebox_broker_transport_linux_userland::unix_socket::validate_peer_process;
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::process::{Pid, PidfdFlags, Signal};

/// Leading argument of the runner mode, which containerd never passes.
pub(crate) const RUNNER_MODE: &str = "__litebox-runner";
/// Descriptor of the socket directory in runners, through which they reach their socket.
const SOCKET_DIR_FD: RawFd = 3;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("runner registry mutex poisoned")
}

/// Runs the runner mode, whose arguments are `<socket> [gated]`, with the shim's log as stdout
/// and stderr.
pub(crate) fn runner_main(args: &[OsString]) -> ! {
    let Some(socket) = args.first() else {
        eprintln!("this mode is private to containerd-shim-litebox-v1");
        std::process::exit(2);
    };
    // A gated runner's stdin is its gate: the daemon writes one byte to start it, and closes the
    // gate without writing if it gives up.
    if args.get(1).is_some_and(|arg| arg == "gated") && io::stdin().read_exact(&mut [0]).is_err() {
        std::process::exit(0);
    }
    let args = litebox_runner_linux_userland::CliArgs {
        program_and_arguments: Vec::new(),
        environment_variables: Vec::new(),
        forward_environment_variables: false,
        unstable: true,
        broker_control_channel: Some(PathBuf::from(socket)),
        broker_proxy_url: None,
    };
    match litebox_runner_linux_userland::run(args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("litebox runner failed: {error:#}");
            std::process::exit(127);
        }
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// The runners of one container, and what spawning them needs.
pub(crate) struct Runners {
    jobs: mpsc::Sender<Job>,
    /// The socket directory, opened `O_PATH`.
    dir: OwnedFd,
    dir_path: PathBuf,
    /// The shim's log, which runners write to.
    log: fs::File,
    state: Mutex<Registry>,
    changed: Condvar,
}

#[derive(Default)]
struct Registry {
    /// Set once the container ends; no runner is spawned after it.
    closed: bool,
    next: u64,
    live: HashMap<u64, Live>,
}

struct Live {
    pid: u32,
    pidfd: Arc<OwnedFd>,
    process: ProcessId,
}

fn kill(pidfd: &OwnedFd) {
    // Fails only once the process is gone.
    let _ = rustix::process::pidfd_send_signal(pidfd, Signal::KILL);
}

impl Runners {
    /// Creates the socket directory `dir_path`, replacing a stale one, and the spawner thread.
    pub(crate) fn new(dir_path: PathBuf) -> io::Result<Arc<Self>> {
        // The FIFO in the daemon's working directory that containerd reads as the shim's log, as
        // the crate's logger writes it. containerd holds its reading end, so this never blocks.
        let log = fs::OpenOptions::new().append(true).open("log")?;
        match fs::remove_dir_all(&dir_path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        fs::DirBuilder::new().mode(0o700).create(&dir_path)?;
        let dir = rustix::fs::open(
            &dir_path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let (jobs, received) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("litebox-spawner".to_owned())
            .spawn(move || {
                for job in received {
                    job();
                }
            })?;
        Ok(Arc::new(Self {
            jobs,
            dir,
            dir_path,
            log,
            state: Mutex::default(),
            changed: Condvar::new(),
        }))
    }

    /// Spawns a runner for the broker process `process`; a `gated` one waits for
    /// [`Runner::open_gate`] before it connects.
    pub(crate) fn spawn(self: &Arc<Self>, process: ProcessId, gated: bool) -> io::Result<Runner> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err(io::Error::other("the container is stopping"));
        }
        let key = state.next;
        state.next += 1;
        let socket = format!("{key}.sock");
        let spawned = (|| -> io::Result<_> {
            let mut command = Command::new("/proc/self/exe");
            command
                .arg(RUNNER_MODE)
                .arg(format!("/proc/self/fd/{SOCKET_DIR_FD}/{socket}"));
            let gate = if gated {
                let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
                command.arg("gated").stdin(read);
                Some(write)
            } else {
                command.stdin(Stdio::null());
                None
            };
            // Native fork needs the broker to adopt clones, which this shim does not do.
            command
                .env_clear()
                .env("LITEBOX_DISABLE_NATIVE_FORK", "1")
                .stdout(self.log.try_clone()?)
                .stderr(self.log.try_clone()?)
                .current_dir("/");
            if let Some(filter) = std::env::var_os("LITEBOX_LOG") {
                command.env("LITEBOX_LOG", filter);
            }
            // Above `SOCKET_DIR_FD`: `dup2` onto its own number would keep it close-on-exec.
            let dir = rustix::io::fcntl_dupfd_cloexec(&self.dir, SOCKET_DIR_FD + 1)?;
            let parent = libc::pid_t::try_from(std::process::id())
                .map_err(|_| io::ErrorKind::InvalidData)?;
            // SAFETY: the hook runs in the forked child before `exec` and only makes
            // async-signal-safe system calls on descriptors it owns.
            unsafe {
                command.pre_exec(move || prepare_child(parent, &dir));
            }
            // Bundle paths may exceed `sun_path`.
            let listener =
                UnixListener::bind(format!("/proc/self/fd/{}/{socket}", self.dir.as_raw_fd()))?;
            listener.set_nonblocking(true)?;
            let (sender, spawned) = mpsc::sync_channel(1);
            let stopped = || io::Error::other("the spawner thread stopped");
            self.jobs
                .send(Box::new(move || {
                    let _ = sender.send(command.spawn());
                }))
                .map_err(|_| stopped())?;
            let mut child = spawned.recv().map_err(|_| stopped())??;
            // The child cannot be reaped yet, so its process ID still names it.
            match rustix::process::pidfd_open(Pid::from_child(&child), PidfdFlags::empty()) {
                Ok(pidfd) => Ok((listener, child, Arc::new(pidfd), gate)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    Err(error.into())
                }
            }
        })();
        let (listener, child, pidfd, gate) = spawned.inspect_err(|_| {
            let _ = rustix::fs::unlinkat(&self.dir, &socket, AtFlags::empty());
        })?;
        state.live.insert(
            key,
            Live {
                pid: child.id(),
                pidfd: Arc::clone(&pidfd),
                process,
            },
        );
        Ok(Runner {
            key,
            child,
            pidfd,
            listener: Some(listener),
            socket,
            gate,
            runners: Arc::clone(self),
        })
    }

    /// Ends the container: no runner is spawned after this, and every runner is killed.
    pub(crate) fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        for live in state.live.values() {
            kill(&live.pidfd);
        }
    }

    /// Kills the runners of `process`, or every runner.
    pub(crate) fn kill(&self, process: Option<ProcessId>) {
        for live in lock(&self.state).live.values() {
            if process.is_none_or(|process| live.process == process) {
                kill(&live.pidfd);
            }
        }
    }

    /// The host process IDs of the live runners.
    pub(crate) fn pids(&self) -> Vec<u32> {
        lock(&self.state)
            .live
            .values()
            .map(|live| live.pid)
            .collect()
    }

    /// The broker processes of the live runners.
    pub(crate) fn processes(&self) -> Vec<ProcessId> {
        lock(&self.state)
            .live
            .values()
            .map(|live| live.process)
            .collect()
    }

    /// Waits up to `timeout` until every runner has been reaped.
    pub(crate) fn wait_reaped(&self, timeout: Duration) -> bool {
        self.changed
            .wait_timeout_while(lock(&self.state), timeout, |state| !state.live.is_empty())
            .expect("runner registry mutex poisoned")
            .0
            .live
            .is_empty()
    }

    pub(crate) fn remove_dir(&self) {
        if let Err(error) = fs::remove_dir_all(&self.dir_path) {
            log::warn!("cannot remove {}: {error}", self.dir_path.display());
        }
    }
}

/// Prepares a runner in the forked child of the daemon `parent`, before `exec`.
fn prepare_child(parent: libc::pid_t, dir: &OwnedFd) -> io::Result<()> {
    let check = |result: libc::c_int| {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    // SAFETY: these system calls take no pointers, and `dir` is an open descriptor.
    unsafe {
        // Runners continue a parent's copied memory image on fork, which needs one layout.
        let persona = libc::personality(0xffff_ffff);
        check(persona)?;
        check(libc::personality(
            libc::c_ulong::from(persona.cast_unsigned()) | libc::ADDR_NO_RANDOMIZE as libc::c_ulong,
        ))?;
        check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL))?;
        // The daemon may have died before the death signal was armed.
        if libc::getppid() != parent {
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }
        // Runners must not hold the daemon's other descriptors, such as other tasks' stdio FIFO
        // ends, which would keep those streams open.
        let closed = libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        );
        if closed < 0 {
            return Err(io::Error::last_os_error());
        }
        check(libc::dup2(dir.as_raw_fd(), SOCKET_DIR_FD))?;
    }
    Ok(())
}

/// A runner and its socket, which this value alone accepts on and reaps. Dropping it kills and
/// reaps the runner.
pub(crate) struct Runner {
    key: u64,
    child: Child,
    pidfd: Arc<OwnedFd>,
    listener: Option<UnixListener>,
    socket: String,
    /// The write end of a gated runner's gate.
    gate: Option<OwnedFd>,
    runners: Arc<Runners>,
}

impl Runner {
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns a function that kills the runner.
    pub(crate) fn killer(&self) -> impl Fn() + Send + Sync + 'static {
        let pidfd = Arc::clone(&self.pidfd);
        move || kill(&pidfd)
    }

    /// Returns a function that waits until the runner exits, without reaping it, and returns
    /// whether it did.
    pub(crate) fn exit_waiter(&self) -> impl FnOnce() -> bool + Send + 'static {
        let pidfd = Arc::clone(&self.pidfd);
        move || loop {
            let mut fds = [PollFd::new(&*pidfd, PollFlags::IN)];
            match rustix::event::poll(&mut fds, None) {
                Err(rustix::io::Errno::INTR) => {}
                result => return result.is_ok(),
            }
        }
    }

    /// Lets a gated runner connect.
    pub(crate) fn open_gate(&mut self) -> io::Result<()> {
        match self.gate.take() {
            Some(gate) => rustix::io::write(&gate, b"1").map(drop).map_err(Into::into),
            None => Ok(()),
        }
    }

    /// Accepts the runner's connection before `deadline`, authenticates it by the runner's
    /// process ID, and removes the socket.
    pub(crate) fn accept(&mut self, deadline: Instant) -> io::Result<UnixStream> {
        let accepted = self.accept_any(deadline);
        self.remove_socket();
        let stream = accepted?;
        // Only this value reaps the runner, so its unreaped process ID cannot have been reused.
        if self.child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the runner exited while connecting",
            ));
        }
        validate_peer_process(&stream, self.child.id())?;
        Ok(stream)
    }

    fn accept_any(&self, deadline: Instant) -> io::Result<UnixStream> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| io::Error::other("the runner was already accepted"))?;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the runner did not connect in time",
                ));
            }
            let mut fds = [
                PollFd::new(listener, PollFlags::IN),
                PollFd::new(&*self.pidfd, PollFlags::IN),
            ];
            poll(&mut fds, deadline)?;
            if !fds[1].revents().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "the runner exited before connecting",
                ));
            }
        }
    }

    fn remove_socket(&mut self) {
        if self.listener.take().is_some() {
            let _ = rustix::fs::unlinkat(&self.runners.dir, &self.socket, AtFlags::empty());
        }
    }

    /// Waits up to `grace` for the runner to exit, kills it if it does not, and reaps it.
    /// Returns its status and whether it had to be killed.
    pub(crate) fn wait(&mut self, grace: Duration) -> (ExitStatus, bool) {
        let mut fds = [PollFd::new(&*self.pidfd, PollFlags::IN)];
        let exited = poll(&mut fds, Instant::now() + grace).is_ok() && !fds[0].revents().is_empty();
        if !exited {
            kill(&self.pidfd);
        }
        // `wait` fails only for a process that is not this one's child, which a runner is.
        let status = self
            .child
            .wait()
            .unwrap_or_else(|_| std::os::unix::process::ExitStatusExt::from_raw(0xff << 8));
        (status, !exited)
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.remove_socket();
        kill(&self.pidfd);
        let _ = self.child.wait();
        lock(&self.runners.state).live.remove(&self.key);
        self.runners.changed.notify_all();
    }
}

/// Polls `fds` until `deadline` (at least once, so a past deadline only checks them), retrying
/// on interruption.
fn poll(fds: &mut [PollFd<'_>], deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = Timespec::try_from(remaining).map_err(|_| io::ErrorKind::InvalidInput)?;
        match rustix::event::poll(fds, Some(&timeout)) {
            Err(rustix::io::Errno::INTR) => {}
            result => return result.map(drop).map_err(Into::into),
        }
    }
}
