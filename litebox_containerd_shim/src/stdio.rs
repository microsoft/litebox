// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A process's standard streams: the host ends that containerd names, `binary://` logging
//! programs, and the threads that copy between the host ends and the guest service.

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use containerd_shim::protos::events::task::TaskIO;
use containerd_shim::protos::ttrpc::context::Context;
use litebox_guest_service_protocol::guest_service::{
    CloseStdinRequest, ReadStreamRequest, WriteStreamRequest,
};
use litebox_guest_service_protocol::guest_service_ttrpc::GuestServiceClient;
use rustix::event::{PollFd, PollFlags, Timespec};
use url::Url;

use crate::{Result, internal, unsupported};

/// The most bytes one read carries.
const CHUNK: u32 = 64 * 1024;

/// How long a logging program may take to exit once its inputs end, before `SIGTERM`.
const LOGGER_GRACE: Duration = Duration::from_secs(1);
/// How long it may take to exit after `SIGTERM`, before `SIGKILL`: containerd's.
const LOGGER_TERM_TIMEOUT: Duration = Duration::from_secs(12);

/// Opens the host end that `uri` names: a FIFO (a path, or `fifo://`), or for an output a
/// regular file (`file://`, percent-decoded as containerd does) to append to, whose missing
/// directories are created as runc's shim creates them; `None` for none. A FIFO is opened
/// read-write, so that opening it never blocks, and an input ends only with `CloseIO`, as with
/// runc.
fn open(uri: &str, input: bool) -> Result<Option<File>> {
    let (path, fifo) = match uri.split_once("://") {
        _ if uri.is_empty() => return Ok(None),
        None => (PathBuf::from(uri), true),
        Some(("fifo", path)) => (PathBuf::from(path), true),
        Some(("file", _)) if !input => (parse(uri)?.1, false),
        _ => return Err(unsupported(format!("the I/O URI {uri:?}"))),
    };
    let mut options = OpenOptions::new();
    if fifo {
        options.read(true).write(true);
        if input {
            options.custom_flags(libc::O_NONBLOCK);
        }
    } else {
        if let Some(parent) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o755)
                .create(parent)
                .map_err(|error| {
                    internal(format!("cannot create {}: {error}", parent.display()))
                })?;
        }
        options.append(true).create(true).mode(0o644);
    }
    let file = options
        .open(&path)
        .map_err(|error| internal(format!("cannot open {}: {error}", path.display())))?;
    Ok(Some(file))
}

/// The URI `uri`, which must have no host, and its percent-decoded path.
fn parse(uri: &str) -> Result<(Url, PathBuf)> {
    let refuse = || unsupported(format!("the I/O URI {uri:?}"));
    let url = Url::parse(uri).map_err(|_| refuse())?;
    let path = url.to_file_path().map_err(|()| refuse())?;
    Ok((url, path))
}

/// The host ends of a process's streams: stdin, stdout and stderr.
pub struct Host {
    pub files: [Option<File>; 3],
    /// After `files`, so that its inputs end before it is reaped.
    pub logger: Option<Logger>,
}

impl Host {
    /// Opens the host ends of `io` for the container `id` of the containerd namespace
    /// `namespace`. As with containerd's runc shim, a `binary://` stdout names a logging program
    /// that reads stderr too, and a terminal's output is all stdout.
    pub fn open(io: &TaskIO, id: &str, namespace: &str) -> Result<Self> {
        let stdin = open(&io.stdin, true)?;
        if io.stdout.starts_with("binary://") {
            let (logger, stdout, stderr) = Logger::spawn(&io.stdout, id, namespace)?;
            return Ok(Self {
                files: [stdin, Some(stdout), (!io.terminal).then_some(stderr)],
                logger: Some(logger),
            });
        }
        let stderr = if io.terminal {
            None
        } else {
            open(&io.stderr, false)?
        };
        Ok(Self {
            files: [stdin, open(&io.stdout, false)?, stderr],
            logger: None,
        })
    }
}

/// A logging program, run as containerd's runc shim runs it: descriptors 3 and 4 read the
/// process's stdout and stderr, and it closes or writes to 5 once ready. Dropping it reaps it,
/// as containerd's runc shim ends it: `SIGTERM`, then `SIGKILL`.
pub struct Logger(Child);

impl Logger {
    /// Spawns the logging program of the `binary://` URI `uri`; returns it once it is ready, and
    /// the write ends of its stdout and stderr.
    fn spawn(uri: &str, id: &str, namespace: &str) -> Result<(Self, File, File)> {
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
            OwnedFd::from(stdout_end).into(),
            OwnedFd::from(stderr_end).into(),
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

/// The threads of one process's streams.
pub struct Pumps {
    /// Disconnected once every output ended.
    outputs: mpsc::Receiver<()>,
    stop: Arc<AtomicBool>,
}

impl Pumps {
    /// Starts copying between the host ends and the streams of the guest service's process
    /// `guest_id`; an output without a host end is drained. The input ends once `closing` is set
    /// and what was readable then is forwarded, and is closed in the guest service at its end,
    /// or at once without a host end (but a terminal's, which would hang the terminal up).
    pub fn start(
        client: &Arc<GuestServiceClient>,
        guest_id: &str,
        [stdin, stdout, stderr]: [Option<File>; 3],
        terminal: bool,
        closing: Arc<AtomicBool>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (done, outputs) = mpsc::channel();
        let (client, guest_id) = (Arc::clone(client), guest_id.to_owned());
        if let Some(fifo) = stdin {
            let (client, guest_id, stop) =
                (Arc::clone(&client), guest_id.clone(), Arc::clone(&stop));
            std::thread::spawn(move || copy_input(&client, guest_id, &fifo, &closing, &stop));
        } else if !terminal {
            close_stdin(&client, guest_id.clone());
        }
        let outputs_of_process = if terminal {
            vec![(false, stdout)]
        } else {
            vec![(false, stdout), (true, stderr)]
        };
        for (is_stderr, sink) in outputs_of_process {
            let (client, guest_id, done) = (Arc::clone(&client), guest_id.clone(), done.clone());
            std::thread::spawn(move || {
                copy_output(&client, guest_id, is_stderr, sink);
                drop(done);
            });
        }
        Self { outputs, stop }
    }

    /// Waits up to `timeout` for every output to end; returns whether they did.
    pub fn drain(&self, timeout: Duration) -> bool {
        self.outputs.recv_timeout(timeout) != Err(mpsc::RecvTimeoutError::Timeout)
    }

    /// Stops the input.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn close_stdin(client: &GuestServiceClient, guest_id: String) {
    let request = CloseStdinRequest {
        exec_id: guest_id,
        ..Default::default()
    };
    // A terminal whose process has not started refuses, and stays open, as runc keeps a terminal
    // open when stdin ends.
    let _ = client.close_stdin(Context::default(), &request);
}

fn copy_input(
    client: &GuestServiceClient,
    guest_id: String,
    fifo: &File,
    closing: &AtomicBool,
    stop: &AtomicBool,
) {
    let mut buffer = vec![0; CHUNK as usize];
    // Once closing, what is left of what was readable then.
    let mut left: Option<usize> = None;
    while !stop.load(Ordering::SeqCst) {
        if closing.load(Ordering::SeqCst) {
            let pending = rustix::io::ioctl_fionread(fifo).unwrap_or(0);
            if *left.get_or_insert(usize::try_from(pending).unwrap_or(usize::MAX)) == 0 {
                break;
            }
        }
        let mut fds = [PollFd::new(fifo, PollFlags::IN)];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        let _ = rustix::event::poll(&mut fds, Some(&timeout));
        let limit = left.unwrap_or(buffer.len()).min(buffer.len());
        let read = match (&*fifo).read(&mut buffer[..limit]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if let Some(left) = &mut left {
            *left -= read;
        }
        let request = WriteStreamRequest {
            exec_id: guest_id.clone(),
            data: buffer[..read].to_vec(),
            ..Default::default()
        };
        if client.write_stdin(Context::default(), &request).is_err() {
            break;
        }
    }
    // Once stopped, the process was released with its streams.
    if !stop.load(Ordering::SeqCst) {
        close_stdin(client, guest_id);
    }
}

/// Copies an output to `sink` until its end; a sink that fails is dropped, and the rest
/// drained, so that the process does not block.
fn copy_output(
    client: &GuestServiceClient,
    guest_id: String,
    stderr: bool,
    mut sink: Option<File>,
) {
    let request = ReadStreamRequest {
        exec_id: guest_id,
        len: CHUNK,
        ..Default::default()
    };
    loop {
        let read = if stderr {
            client.read_stderr(Context::default(), &request)
        } else {
            client.read_stdout(Context::default(), &request)
        };
        let Ok(response) = read else { break };
        if response.data.is_empty() {
            break;
        }
        if let Some(file) = &mut sink
            && file.write_all(&response.data).is_err()
        {
            sink = None;
        }
    }
}
