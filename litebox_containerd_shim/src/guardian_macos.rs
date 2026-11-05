// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS broker supervision without a subreaper, pidfds, or a parent-death signal.
//!
//! The guardian leads a host process group containing the broker and every runner. Guest
//! `setsid`/`setpgid` calls are virtual: they do not let a runner leave that host group. When the
//! daemon's lifeline closes or the broker exits, the guardian kills the whole group, itself
//! included. Orphans are reaped by launchd. The daemon also kills the group if the guardian dies.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream;
use std::process::Command;

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::process::Signal;

pub const GUARDIAN_MODE: &str = "__litebox-guardian";
pub const LIFELINE_FD: RawFd = 3;

/// Runs the guardian in the private process group established by the daemon.
pub fn main(args: &[OsString]) -> ! {
    if let Err(error) = guard(args) {
        eprintln!("litebox guardian: {error}");
    }
    // The group leader is still alive, so its group ID cannot have been reused. Killing the
    // group also handles a broker that failed after starting a runner.
    let _ = rustix::process::kill_process_group(rustix::process::getpid(), Signal::KILL);
    std::process::exit(125)
}

fn guard(args: &[OsString]) -> io::Result<()> {
    let [temp, program, broker_args @ ..] = args else {
        return Err(io::Error::other("this mode is private to the shim"));
    };
    if rustix::process::getpgrp() != rustix::process::getpid() {
        return Err(io::Error::other(
            "the guardian must lead its own process group",
        ));
    }
    // SAFETY: F_GETFD takes only integers.
    if unsafe { libc::fcntl(LIFELINE_FD, libc::F_GETFD) } < 0 {
        return Err(io::Error::other("no lifeline"));
    }
    // SAFETY: the daemon passes the lifeline here; no other object owns it.
    let lifeline = unsafe { UnixStream::from_raw_fd(LIFELINE_FD) };
    rustix::io::fcntl_setfd(&lifeline, rustix::io::FdFlags::CLOEXEC)?;
    let mut broker = Command::new(program)
        .args(broker_args)
        .env("TMPDIR", temp)
        .spawn()?;
    (&lifeline).write_all(&broker.id().to_le_bytes())?;
    // Unlike Linux there is no /proc/self/fd alias for a long TMPDIR. StateDir supplies a short
    // directory instead. Polling also avoids reaping any of the shim's other children.
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    loop {
        if broker.try_wait()?.is_some() {
            return Ok(());
        }
        let mut fds = [PollFd::new(&lifeline, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => {}
            Ok(_) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}
