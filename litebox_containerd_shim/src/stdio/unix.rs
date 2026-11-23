// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! FIFO host ends are non-blocking, so that a copier can always stop; `binary://` logging programs.

use std::borrow::Cow;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};

use super::{INPUT_POLL, WRITE_POLL, parse};
use crate::{Result, internal};

/// How long a logging program may take to exit once its inputs end, before `SIGTERM`.
const LOGGER_GRACE: Duration = Duration::from_secs(1);
/// How long it may take to exit after `SIGTERM`, before `SIGKILL`: containerd's.
const LOGGER_TERM_TIMEOUT: Duration = Duration::from_secs(12);

/// Read-write, to avoid blocking; so stdin gets EOF only from `CloseIO`.
pub fn open_fifo(path: &Path, _input: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

pub fn open_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .open(path)
}

pub fn create_dirs(path: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o755).create(path)
}

pub struct Output(File);

impl Output {
    #[expect(
        clippy::unnecessary_wraps,
        reason = "as fallible as Windows' `Output::new`"
    )]
    pub fn new(file: File) -> io::Result<Self> {
        Ok(Self(file))
    }

    /// Waits without a time limit while a non-blocking FIFO is full, until `deleted` is set (seen
    /// within [`WRITE_POLL`]) or its reader hangs up.
    pub fn write_all(&self, mut data: &[u8], deleted: &AtomicBool) -> io::Result<()> {
        while !data.is_empty() {
            match (&self.0).write(data) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => data = &data[written..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if deleted.load(Ordering::SeqCst) {
                        return Err(error);
                    }
                    self.wait_writable()?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Fails once the reader hung up.
    fn wait_writable(&self) -> io::Result<()> {
        let timeout = Timespec::try_from(WRITE_POLL).expect("the poll interval fits a timespec");
        let mut fds = [PollFd::new(&self.0, PollFlags::OUT)];
        let _ = rustix::event::poll(&mut fds, Some(&timeout));
        if fds[0].revents().intersects(PollFlags::ERR | PollFlags::HUP) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

/// 0 if unknown.
pub fn pending(fifo: &File) -> usize {
    rustix::io::ioctl_fionread(fifo)
        .map_or(0, |pending| usize::try_from(pending).unwrap_or(usize::MAX))
}

/// Waits up to [`INPUT_POLL`]; then reading is always safe, as the FIFO is non-blocking.
pub fn wait_readable(fifo: &File) -> bool {
    let timeout = Timespec::try_from(INPUT_POLL).expect("the poll interval fits a timespec");
    let _ = rustix::event::poll(&mut [PollFd::new(fifo, PollFlags::IN)], Some(&timeout));
    true
}

/// A logging program, run as containerd's runc shim runs it: descriptors 3 and 4 read the
/// process's stdout and stderr, and it closes or writes to 5 once ready. Dropping it reaps it,
/// as containerd's runc shim ends it: `SIGTERM`, then `SIGKILL`.
pub struct Logger(Child);

impl Logger {
    /// Spawns the logging program of the `binary://` URI `uri`; returns it once it is ready, and
    /// the write ends of its stdout and stderr.
    pub fn spawn(uri: &str, id: &str, namespace: &str) -> Result<(Self, Output, Output)> {
        let (url, program) = parse(uri)?;
        let failed = |error: &dyn std::fmt::Display| {
            internal(format!(
                "cannot start the logging program {}: {error}",
                program.display()
            ))
        };
        // Each query pair is two arguments, decoded as Go's `url.Query` does.
        let args = url.query_pairs().flat_map(|(key, value)| [key, value]);
        let (stdout, stdout_end) = io::pipe().map_err(|error| failed(&error))?;
        let (stderr, stderr_end) = io::pipe().map_err(|error| failed(&error))?;
        let (ready, ready_end) = io::pipe().map_err(|error| failed(&error))?;
        // Above 5, so that `dup2` onto 3 to 5 neither clobbers them nor keeps them close-on-exec.
        let mut inherited = Vec::new();
        for fd in [stdout.as_fd(), stderr.as_fd(), ready_end.as_fd()] {
            let fd = rustix::io::fcntl_dupfd_cloexec(fd, 6).map_err(|error| failed(&error))?;
            inherited.push(fd);
        }
        let mut command = Command::new(&program);
        command
            .args(args.map(Cow::into_owned))
            .env_clear()
            .env("CONTAINER_ID", id)
            .env("CONTAINER_NAMESPACE", namespace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the hook makes async-signal-safe calls only, on descriptors it owns.
        unsafe {
            command.pre_exec(move || {
                for (fd, target) in inherited.iter().zip(3..) {
                    if libc::dup2(fd.as_raw_fd(), target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut logger = Self(command.spawn().map_err(|error| failed(&error))?);
        drop((command, stdout, stderr, ready_end));
        // Ready at EOF or a byte, without a time limit, as containerd does.
        let ready = loop {
            match (&ready).read(&mut [0]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                read => break read,
            }
        };
        if let Err(error) = ready {
            let _ = logger.0.kill();
            return Err(failed(&error));
        }
        Ok((
            logger,
            Output(OwnedFd::from(stdout_end).into()),
            Output(OwnedFd::from(stderr_end).into()),
        ))
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        let pid = rustix::process::Pid::from_child(&self.0);
        let exited = crate::exits_within(&self.0, LOGGER_GRACE).and_then(|exited| {
            if !exited {
                rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
            }
            crate::wait_or_kill(&mut self.0, Some(LOGGER_TERM_TIMEOUT))
        });
        match exited {
            Ok(Some(_)) => {}
            Ok(None) => log::warn!("the logging program did not exit in time; killed it"),
            Err(error) => {
                let _ = self.0.kill();
                let _ = self.0.wait();
                log::warn!("cannot wait for the logging program: {error}; killed it");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::Logger;

    #[test]
    fn a_child_that_cannot_be_waited_for_is_killed_and_reaped() {
        // Its process's descriptor limit is lowered: only safe with a process to itself.
        if std::env::var_os("NEXTEST_EXECUTION_MODE").is_none_or(|mode| mode != "process-per-test")
        {
            return;
        }
        let spawn = || {
            std::process::Command::new("sleep")
                .arg("60")
                .spawn()
                .unwrap()
        };
        let (mut hook, logger) = (spawn(), spawn());
        let pids = [hook.id(), logger.id()];
        // No descriptor is left for a pidfd.
        let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        let none = rustix::process::Rlimit {
            current: Some(0),
            maximum: limit.maximum,
        };
        rustix::process::setrlimit(rustix::process::Resource::Nofile, none).unwrap();
        let waited = crate::wait_or_kill(&mut hook, Some(Duration::from_secs(60)));
        drop(Logger(logger));
        rustix::process::setrlimit(rustix::process::Resource::Nofile, limit).unwrap();
        assert!(waited.is_err());
        for pid in pids {
            assert!(
                !std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "{pid}"
            );
        }
    }
}
