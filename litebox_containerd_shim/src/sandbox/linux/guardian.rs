// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker's guardian: this executable in a private mode, the broker's parent, so that no
//! broker process outlives the daemon, which it would not notice.
//!
//! The guardian is a child subreaper, so runners orphaned below it become its children. It holds
//! a lifeline to the daemon, a socket that ends when the daemon dies or stops the container; then,
//! or when one of its children exits, it kills and reaps everything below it, and exits with the
//! broker's status (the VMM's for the VM). Its children die with it (their parent-death
//! signal), and the daemon kills the guardian's process group, which they share, if the guardian
//! itself was killed.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::os::fd::{AsFd, AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::fs::{Mode, OFlags};
use rustix::process::{Pid, PidfdFlags, Signal};

/// The leading argument of the broker's guardian mode, which containerd never passes.
pub const GUARDIAN_MODE: &str = "__litebox-guardian";
/// The leading argument of the VM's guardian mode, which containerd never passes.
pub const VM_GUARDIAN_MODE: &str = "__litebox-vm-guardian";
/// The guardian's end of the lifeline.
pub const LIFELINE_FD: RawFd = 3;
/// A `listen` daemon's listening socket (see [`guard_vm`]).
pub const LISTENER_FD: RawFd = 3;
/// The VMM's connection to the socket of its `connect` daemon (see [`guard_vm`]).
pub const DEVICE_FD: RawFd = 4;
/// How long a `connect` daemon may take to listen on its socket.
const DAEMON_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs the guardian `guard` ([`guard_broker`] or [`guard_vm`]) with `args`, and exits.
pub(super) fn main(guard: fn(&[OsString]) -> io::Result<i32>, args: &[OsString]) -> ! {
    // The broker's sockets are its user's only, whatever containerd's umask.
    rustix::process::umask(Mode::from_raw_mode(0o077));
    let code = guard(args);
    std::process::exit(code.unwrap_or_else(|error| {
        eprintln!("litebox guardian: {error}");
        125
    }))
}

/// Takes the lifeline, and makes this process a child subreaper.
fn lifeline() -> io::Result<UnixStream> {
    // SAFETY: F_GETFD takes only integers.
    if unsafe { libc::fcntl(LIFELINE_FD, libc::F_GETFD) } < 0 {
        return Err(io::Error::other("no lifeline"));
    }
    // SAFETY: the daemon passes the lifeline there, which nothing else owns.
    let lifeline = unsafe { UnixStream::from_raw_fd(LIFELINE_FD) };
    rustix::io::fcntl_setfd(&lifeline, rustix::io::FdFlags::CLOEXEC)?;
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))?;
    Ok(lifeline)
}

/// Spawns `command` as a child that dies with this process, and a pidfd of it.
fn spawn(command: &mut Command) -> io::Result<(Child, OwnedFd)> {
    let me = std::process::id();
    // SAFETY: the hook makes async-signal-safe calls only.
    unsafe {
        command.pre_exec(move || {
            // The guardian may have died before the death signal was armed.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                || u32::try_from(libc::getppid()) != Ok(me)
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|error| {
        let program = Path::new(command.get_program()).display();
        io::Error::new(error.kind(), format!("cannot start {program}: {error}"))
    })?;
    let pidfd = rustix::process::pidfd_open(Pid::from_child(&child), PidfdFlags::empty())?;
    Ok((child, pidfd))
}

/// The broker's guardian, with the broker's temporary directory, how to give it (`plain` or
/// `fd`), and the broker's program and arguments.
pub(super) fn guard_broker(args: &[OsString]) -> io::Result<i32> {
    let [temp, how, program, broker_args @ ..] = args else {
        return Err(io::Error::other("this mode is private to the shim"));
    };
    let lifeline = lifeline()?;
    // The broker creates its sockets there, a path that could be too long for a socket's address:
    // with `fd`, it reaches it through this descriptor instead (see `Broker::spawn`).
    let temp_fd;
    let tmpdir: OsString = match how.to_str() {
        Some("plain") => temp.clone(),
        Some("fd") => {
            let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
            temp_fd = rustix::fs::open(temp, flags, Mode::empty())?;
            format!("/proc/{}/fd/{}", std::process::id(), temp_fd.as_raw_fd()).into()
        }
        _ => return Err(io::Error::other("this mode is private to the shim")),
    };
    let mut command = Command::new(program);
    command.args(broker_args).env("TMPDIR", tmpdir);
    let broker = spawn(&mut command)?;
    guard(&lifeline, broker, &[])
}

/// Has `command` take `fd` as `number` (above which `fd` must be: `dup2` onto its own number would
/// keep it close-on-exec).
fn pass_fd(command: &mut Command, fd: OwnedFd, number: RawFd) {
    // SAFETY: the hook makes async-signal-safe calls only, on a descriptor it owns.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd.as_raw_fd(), number) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The VM's guardian, with the VM's device daemons, each `connect SOCKET PROGRAM ARGS...` or
/// `listen SOCKET PROGRAM ARGS...`, and then the VMM's command, separated by `--` (see
/// `vm::guardian_arguments`):
///
/// - `connect`: a daemon that listens on `SOCKET`, to which the guardian connects once it does, for
///   the VMM to take as [`DEVICE_FD`]; one at most.
/// - `listen`: a daemon that takes `SOCKET`, which the guardian binds, as [`LISTENER_FD`], so that
///   the VMM may connect to it at once.
pub(super) fn guard_vm(args: &[OsString]) -> io::Result<i32> {
    let private = || io::Error::other("this mode is private to the shim");
    let mut commands: Vec<&[OsString]> = args.split(|arg| arg == "--").collect();
    let Some((vmm, vmm_args)) = commands.pop().and_then(<[OsString]>::split_first) else {
        return Err(private());
    };
    let lifeline = lifeline()?;
    let (mut daemons, mut connection) = (Vec::new(), None);
    for daemon in commands {
        let [mode, socket, program, daemon_args @ ..] = daemon else {
            return Err(private());
        };
        let mut command = Command::new(program);
        command.args(daemon_args);
        match mode.to_str() {
            Some("listen") => {
                let listener = UnixListener::bind(socket)?;
                let listener = rustix::io::fcntl_dupfd_cloexec(listener, LISTENER_FD + 1)?;
                pass_fd(&mut command, listener, LISTENER_FD);
                daemons.push(spawn(&mut command)?.1);
            }
            Some("connect") if connection.is_none() => {
                let (_, daemon) = spawn(&mut command)?;
                let connected = connect_daemon(Path::new(socket), &lifeline, &daemon)?;
                connection = Some(rustix::io::fcntl_dupfd_cloexec(connected, DEVICE_FD + 1)?);
                daemons.push(daemon);
            }
            _ => return Err(private()),
        }
    }
    let mut command = Command::new(vmm);
    command.args(vmm_args);
    if let Some(connection) = connection {
        pass_fd(&mut command, connection, DEVICE_FD);
    }
    let vm = spawn(&mut command)?;
    // The VMM's copy alone keeps the connection, so that the daemon sees it end with the VMM.
    drop(command);
    guard(&lifeline, vm, &daemons)
}

/// Connects to a `connect` daemon's `socket` once it listens, for the VMM to take: a VMM's
/// connection may fail if refused, and a probe may end the daemon's one session. Waits up to
/// [`DAEMON_TIMEOUT`] while the `lifeline` and the `daemon_pidfd` are not readable.
fn connect_daemon(
    socket: &Path,
    lifeline: &impl AsFd,
    daemon_pidfd: &impl AsFd,
) -> io::Result<UnixStream> {
    let deadline = Instant::now() + DAEMON_TIMEOUT;
    let poll_interval = Timespec::try_from(Duration::from_millis(10)).expect("in range");
    loop {
        let refused = match UnixStream::connect(socket) {
            Ok(connection) => return Ok(connection),
            Err(error) => error,
        };
        let mut fds = [
            PollFd::new(lifeline, PollFlags::IN),
            PollFd::new(daemon_pidfd, PollFlags::IN),
        ];
        let why = match rustix::event::poll(&mut fds, Some(&poll_interval)) {
            Ok(0) | Err(rustix::io::Errno::INTR) if Instant::now() < deadline => continue,
            Ok(0) | Err(rustix::io::Errno::INTR) => "did not listen in time",
            _ => "exited, or the lifeline ended, before it listened",
        };
        return Err(io::Error::other(format!(
            "the device daemon {why} on {}: {refused}",
            socket.display()
        )));
    }
}

/// Reports the pid of `main`, the broker's, on the `lifeline`, and waits for the lifeline's end,
/// or `main`'s, or the end of a child of the pidfds `helpers`. Then kills and reaps every child,
/// and returns `main`'s status.
fn guard(
    lifeline: &UnixStream,
    (main, main_pidfd): (Child, OwnedFd),
    helpers: &[OwnedFd],
) -> io::Result<i32> {
    // The children's stdout is their own from here on, so that the daemon sees it end with them.
    let null = std::fs::File::open("/dev/null")?;
    // SAFETY: replacing descriptor 1 invalidates no owned descriptor.
    unsafe { libc::dup2(null.as_raw_fd(), 1) };
    if (&*lifeline).write_all(&main.id().to_le_bytes()).is_ok() {
        // The daemon never writes: the lifeline is readable once it ends.
        let mut fds = vec![
            PollFd::new(lifeline, PollFlags::IN),
            PollFd::new(&main_pidfd, PollFlags::IN),
        ];
        fds.extend(
            helpers
                .iter()
                .map(|helper| PollFd::new(helper, PollFlags::IN)),
        );
        while rustix::event::poll(&mut fds, None) == Err(rustix::io::Errno::INTR) {}
    }
    let pid = Pid::from_child(&main);
    let _ = rustix::process::kill_process(pid, Signal::KILL);
    let me = std::process::id();
    // Kills and reaps every child, the runners orphaned here meanwhile included, until none is
    // left; unreaped children keep their pids, so the kills reach only them.
    let kill_children = || {
        for child in children(me) {
            let _ = rustix::process::kill_process(child, Signal::KILL);
        }
    };
    kill_children();
    let mut code = 125;
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid, writable int.
        match unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) } {
            // None has exited since: kill those orphaned here meanwhile.
            0 => {
                std::thread::sleep(Duration::from_millis(5));
                kill_children();
            }
            reaped if reaped == pid.as_raw_nonzero().get() => {
                code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                };
            }
            reaped if reaped > 0 => {}
            _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
            _ => return Ok(code),
        }
    }
}

/// The children of the process `parent`, from `/proc/<pid>/stat` (which, unlike
/// `/proc/<pid>/task/<tid>/children`, every kernel has).
fn children(parent: u32) -> Vec<Pid> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| {
            let child = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(format!("/proc/{child}/stat")).ok()?;
            let its_parent: u32 = stat.rsplit_once(") ")?.1.split(' ').nth(1)?.parse().ok()?;
            (its_parent == parent)
                .then(|| Pid::from_raw(child))
                .flatten()
        })
        .collect()
}
