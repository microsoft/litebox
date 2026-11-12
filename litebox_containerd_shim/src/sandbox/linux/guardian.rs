// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The broker's guardian: this executable in a private mode, the broker's parent, so that neither
//! the broker nor its runners outlive the daemon, which runners would not notice.
//!
//! The guardian is a child subreaper, so runners orphaned below it become its children. It holds
//! a lifeline to the daemon, a socket that ends when the daemon dies or stops the container; then,
//! or when the broker exits, it kills and reaps everything below it, and exits with the broker's
//! status. The broker dies with the guardian (its parent-death signal), and the daemon kills the
//! guardian's process group, which the runners share, if the guardian itself was killed.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::process::Command;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags};
use rustix::fs::{Mode, OFlags};
use rustix::process::{Pid, PidfdFlags, Signal};

/// The leading argument of the guardian mode, which containerd never passes.
pub const GUARDIAN_MODE: &str = "__litebox-guardian";
/// The guardian's end of the lifeline.
pub const LIFELINE_FD: RawFd = 3;

/// Runs the guardian with the broker's temporary directory, how to give it (`plain` or `fd`), and
/// the broker's program and arguments.
pub fn main(args: &[OsString]) -> ! {
    let code = guard(args).unwrap_or_else(|error| {
        eprintln!("litebox guardian: {error}");
        125
    });
    std::process::exit(code)
}

fn guard(args: &[OsString]) -> io::Result<i32> {
    let [temp, how, program, broker_args @ ..] = args else {
        return Err(io::Error::other("this mode is private to the shim"));
    };
    // SAFETY: F_GETFD takes only integers.
    if unsafe { libc::fcntl(LIFELINE_FD, libc::F_GETFD) } < 0 {
        return Err(io::Error::other("no lifeline"));
    }
    // SAFETY: the daemon passes the lifeline there, which nothing else owns.
    let lifeline = unsafe { UnixStream::from_raw_fd(LIFELINE_FD) };
    rustix::io::fcntl_setfd(&lifeline, rustix::io::FdFlags::CLOEXEC)?;
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))?;
    let me = std::process::id();
    // The broker creates its sockets there, a path that could be too long for a socket's address:
    // with `fd`, it reaches it through this descriptor instead (see `Broker::spawn`).
    let temp_fd;
    let tmpdir: OsString = match how.to_str() {
        Some("plain") => temp.clone(),
        Some("fd") => {
            let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
            temp_fd = rustix::fs::open(temp, flags, Mode::empty())?;
            format!("/proc/{me}/fd/{}", temp_fd.as_raw_fd()).into()
        }
        _ => return Err(io::Error::other("this mode is private to the shim")),
    };
    // The broker's sockets are its user's only, whatever containerd's umask.
    rustix::process::umask(Mode::from_raw_mode(0o077));
    let mut command = Command::new(program);
    command.args(broker_args).env("TMPDIR", tmpdir);
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
    let broker = command.spawn()?;
    // The broker's stdout is its own from here on, so that the daemon sees it end with it.
    let null = std::fs::File::open("/dev/null")?;
    // SAFETY: replacing descriptor 1 invalidates no owned descriptor.
    unsafe { libc::dup2(null.as_raw_fd(), 1) };
    let pid = Pid::from_child(&broker);
    let pidfd = rustix::process::pidfd_open(pid, PidfdFlags::empty())?;
    if (&lifeline).write_all(&broker.id().to_le_bytes()).is_ok() {
        // The daemon never writes: the lifeline is readable once it ends.
        let mut fds = [
            PollFd::new(&lifeline, PollFlags::IN),
            PollFd::new(&pidfd, PollFlags::IN),
        ];
        while rustix::event::poll(&mut fds, None) == Err(rustix::io::Errno::INTR) {}
    }
    let _ = rustix::process::kill_process(pid, Signal::KILL);
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
