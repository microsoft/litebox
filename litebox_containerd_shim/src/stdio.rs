// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A task's standard streams: the host ends containerd names, and the pumps that copy between
//! them and broker pipes.
//!
//! The container's authority, a broker process that never runs, owns the host-side ends of every
//! task's pipes; the task inherits the other ends as descriptors 0, 1 and 2. Each stream has a
//! thread, which waits for the authority's readiness notifications on the broker side and for
//! `poll` on the host side.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use litebox::pipes::HalfPipeType;
use litebox_broker_core::readiness::ReadinessSink;
use litebox_broker_core::{BrokerError, BrokerProcess, pipe};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fs::FileOpenFlags;
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_common_linux::program_startup::{InheritedFd, InheritedFdKind};
use rustix::event::{EventfdFlags, PollFd, PollFlags};
use rustix::pipe::PipeFlags;

use crate::error::{Error, Result};
use crate::runner;

const PIPE_CAPACITY: u64 = 64 * 1024;
/// Writes up to this size are atomic, as Linux's `PIPE_BUF`.
const PIPE_ATOMIC_WRITE: u64 = 4096;
/// At most `MAX_PIPE_TRANSFER_SIZE`, the broker's limit per pipe read or write.
const CHUNK: usize = 16 * 1024;
/// A broker pipe is rechecked this often even without a readiness notification.
const BROKER_POLL: Duration = Duration::from_secs(1);
/// How long aborted pumps may take to stop, which they do at once unless a host write hangs.
const ABORT_TIMEOUT: Duration = Duration::from_secs(1);
/// How long a logging binary may take to become ready, and to exit once its inputs ended.
const LOGGER_TIMEOUT: Duration = Duration::from_secs(10);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("stdio mutex poisoned")
}

/// The host ends of a task's standard streams, as containerd names them.
pub(crate) struct Host {
    // Before `logger`, so that the outputs end before it is reaped.
    fds: [OwnedFd; 3],
    logger: Option<Logger>,
}

/// Opens the host ends of `stdin`, `stdout` and `stderr` as containerd names them for the process
/// `id` of the containerd namespace `namespace`, without blocking.
///
/// An empty URI is `/dev/null`; a path or `fifo://` URI is a FIFO; `file://` (outputs only) is a
/// regular file appended to. URI paths are percent-decoded, as containerd escapes them. FIFOs are
/// opened for both reading and writing: an output then blocks instead of breaking when its reader
/// goes away, and, as with runc, an input ends only with `CloseIO`, not when a client that writes
/// it closes its end.
///
/// As containerd's runc shim does, a `binary://` stdout names a logging binary that reads both
/// outputs, and `stderr` is then unused. `loggers` counts it until it is reaped.
pub(crate) fn open(
    stdin: &str,
    stdout: &str,
    stderr: &str,
    id: &str,
    namespace: &str,
    loggers: &Arc<Loggers>,
) -> Result<Host> {
    let open = |uri: &str, input: bool| -> Result<OwnedFd> {
        let unsupported = || Error::invalid(format!("unsupported I/O URI {uri}"));
        let (path, fifo) = match uri.split_once("://") {
            _ if uri.is_empty() => (PathBuf::from("/dev/null"), false),
            None if uri.starts_with('/') => (PathBuf::from(uri), true),
            Some(("fifo", path)) if path.starts_with('/') => {
                (percent_decode(path).ok_or_else(unsupported)?, true)
            }
            Some(("file", path)) if path.starts_with('/') && !input => {
                (percent_decode(path).ok_or_else(unsupported)?, false)
            }
            _ => return Err(unsupported()),
        };
        let null = path == Path::new("/dev/null");
        let mut options = OpenOptions::new();
        options
            .read(input || fifo)
            .write(fifo || !input)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
        if !input && !fifo && !null {
            options.append(true).create(true).mode(0o644);
        }
        let path = path.as_path();
        let file = options
            .open(path)
            .map_err(|error| Error::io(&format!("cannot open {}", path.display()), &error))?;
        let file_type = file
            .metadata()
            .map_err(|error| Error::io(&format!("cannot inspect {}", path.display()), &error))?
            .file_type();
        let expected = if fifo {
            file_type.is_fifo()
        } else {
            file_type.is_file() || null
        };
        if !expected {
            return Err(Error::invalid(format!(
                "{} has the wrong file type",
                path.display()
            )));
        }
        Ok(file.into())
    };
    let stdin = open(stdin, true)?;
    if let Some(uri) = stdout.strip_prefix("binary://") {
        let (logger, stdout, stderr) = Logger::spawn(uri, id, namespace, loggers)?;
        return Ok(Host {
            fds: [stdin, stdout, stderr],
            logger: Some(logger),
        });
    }
    Ok(Host {
        fds: [stdin, open(stdout, false)?, open(stderr, false)?],
        logger: None,
    })
}

/// The logging binaries that are not reaped yet.
#[derive(Default)]
pub(crate) struct Loggers {
    live: Mutex<usize>,
    reaped: Condvar,
}

impl Loggers {
    /// Waits until every logging binary is reaped, at most as long as that takes once the pumps
    /// of their tasks were stopped, and returns whether they were.
    pub(crate) fn wait_reaped(&self) -> bool {
        // Stopped pumps end within `ABORT_TIMEOUT`, then the last one gives the binary
        // `LOGGER_TIMEOUT` to exit before it kills and reaps it, which takes far less than
        // another `ABORT_TIMEOUT`.
        let timeout = ABORT_TIMEOUT + LOGGER_TIMEOUT + ABORT_TIMEOUT;
        *self
            .reaped
            .wait_timeout_while(lock(&self.live), timeout, |live| *live > 0)
            .expect("stdio mutex poisoned")
            .0
            == 0
    }
}

/// A logging binary, which reads a task's stdout and stderr as containerd's runc shim runs it.
/// Dropping it reaps it, once its inputs ended.
struct Logger {
    child: Child,
    loggers: Arc<Loggers>,
}

impl Logger {
    /// Spawns the logging binary of the `binary://` URI whose rest is `uri` for the process `id`
    /// of the containerd namespace `namespace`, counted in `loggers`, waits until it is ready,
    /// and returns it and the write ends of its stdout and stderr.
    fn spawn(
        uri: &str,
        id: &str,
        namespace: &str,
        loggers: &Arc<Loggers>,
    ) -> Result<(Self, OwnedFd, OwnedFd)> {
        let unsupported = || Error::invalid(format!("unsupported I/O URI binary://{uri}"));
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let path = percent_decode(path)
            .filter(|path| path.is_absolute())
            .ok_or_else(unsupported)?;
        // Each query pair `key=value` is the two arguments `key value`.
        let mut args = Vec::new();
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            for arg in [key, value] {
                let arg = percent_decode(&arg.replace('+', " ")).ok_or_else(unsupported)?;
                args.push(arg);
            }
        }
        let failed = |error: io::Error| Error::io("cannot start the logging binary", &error);
        let pipe =
            || rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|error| failed(error.into()));
        let (stdout, stdout_write) = pipe()?;
        let (stderr, stderr_write) = pipe()?;
        let (ready_read, ready) = pipe()?;
        // The binary's descriptors 3 to 5, above them: `dup2` onto its own number would keep a
        // descriptor close-on-exec.
        let mut inherited = Vec::new();
        for fd in [&stdout, &stderr, &ready] {
            inherited.push(
                rustix::io::fcntl_dupfd_cloexec(fd, 6).map_err(|error| failed(error.into()))?,
            );
        }
        let mut command = Command::new(&path);
        command
            .args(&args)
            .env_clear()
            .env("CONTAINER_ID", id)
            .env("CONTAINER_NAMESPACE", namespace)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the hook runs in the forked child before `exec` and only makes async-signal-safe
        // system calls on descriptors it owns.
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
        let child = command.spawn().map_err(failed)?;
        *lock(&loggers.live) += 1;
        let mut logger = Self {
            child,
            loggers: Arc::clone(loggers),
        };
        drop((command, stdout, stderr, ready));
        let ready = (|| {
            // It closes or writes to its end of the ready pipe once it is ready.
            let mut fds = [PollFd::new(&ready_read, PollFlags::IN)];
            runner::poll(&mut fds, Instant::now() + LOGGER_TIMEOUT).map_err(failed)?;
            if fds[0].revents().is_empty() {
                return Err(Error::internal(
                    "the logging binary did not become ready in time",
                ));
            }
            // As for FIFOs, so that aborted pumps never block on a write.
            for fd in [&stdout_write, &stderr_write] {
                rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK)
                    .map_err(|error| failed(error.into()))?;
            }
            Ok(())
        })();
        if let Err(error) = ready {
            // Killed at once: it cannot see its inputs end while their write ends are open, so
            // dropping it would wait `LOGGER_TIMEOUT` in vain.
            let _ = logger.child.kill();
            return Err(error);
        }
        Ok((logger, stdout_write, stderr_write))
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        // It exits once its inputs end, unless it hangs.
        let _ = runner::reap(&mut self.child, Some(Instant::now() + LOGGER_TIMEOUT));
        *lock(&self.loggers.live) -= 1;
        self.loggers.reaped.notify_all();
    }
}

/// Decodes the path of a URI, which has no query or fragment.
fn percent_decode(path: &str) -> Option<PathBuf> {
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'?' | b'#' => return None,
            b'%' => {
                let digits = [bytes.next()?, bytes.next()?];
                if !digits.iter().all(u8::is_ascii_hexdigit) {
                    return None;
                }
                decoded.push(u8::from_str_radix(std::str::from_utf8(&digits).ok()?, 16).ok()?);
            }
            byte => decoded.push(byte),
        }
    }
    Some(PathBuf::from(OsString::from_vec(decoded)))
}

/// Wakes the pumps whenever an object of the authority changes readiness.
#[derive(Default)]
pub(crate) struct Wake {
    generation: Mutex<u64>,
    changed: Condvar,
}

impl Wake {
    fn generation(&self) -> u64 {
        *lock(&self.generation)
    }

    fn bump(&self) {
        *lock(&self.generation) += 1;
        self.changed.notify_all();
    }

    /// Waits until the generation passes `seen`, or for at most [`BROKER_POLL`].
    fn wait(&self, seen: u64) {
        let _ = self
            .changed
            .wait_timeout_while(lock(&self.generation), BROKER_POLL, |generation| {
                *generation == seen
            })
            .expect("stdio mutex poisoned");
    }
}

impl ReadinessSink for Wake {
    fn max_tracked_objects(&self) -> usize {
        usize::MAX
    }

    fn publish(&self, _: ObjectHandle, _: ReadinessFlags) -> litebox_broker_core::Result<()> {
        self.bump();
        Ok(())
    }

    fn republish(&self, _: ObjectHandle, _: ReadinessFlags) -> litebox_broker_core::Result<()> {
        self.bump();
        Ok(())
    }

    fn retire(&self, _: ObjectHandle) {}
}

/// What a pump does; requests only ever advance it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
enum Mode {
    Run,
    /// Input only: forward what is readable when the pump first sees this mode, then end the
    /// stream.
    Close,
    Abort,
}

/// Controls one pump thread.
struct Control {
    /// The mode, and whether the thread finished.
    state: Mutex<(Mode, bool)>,
    finished: Condvar,
    /// Readable once the mode changed, to end a `poll` on the host descriptor.
    event: OwnedFd,
}

impl Control {
    fn new() -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            state: Mutex::new((Mode::Run, false)),
            finished: Condvar::new(),
            event: rustix::event::eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?,
        }))
    }

    fn mode(&self) -> Mode {
        lock(&self.state).0
    }

    fn request(&self, mode: Mode, wake: &Wake) {
        let mut state = lock(&self.state);
        if mode > state.0 {
            state.0 = mode;
            let _ = rustix::io::write(&self.event, &1u64.to_ne_bytes());
            wake.bump();
        }
    }

    fn finish(&self) {
        lock(&self.state).1 = true;
        self.finished.notify_all();
    }

    fn wait(&self, deadline: Instant) -> bool {
        let timeout = deadline.saturating_duration_since(Instant::now());
        self.finished
            .wait_timeout_while(lock(&self.state), timeout, |state| !state.1)
            .expect("stdio mutex poisoned")
            .0
            .1
    }
}

/// The pumps of one task's standard streams.
pub(crate) struct TaskIo {
    stdin: Arc<Control>,
    outputs: [Arc<Control>; 2],
    wake: Arc<Wake>,
}

impl TaskIo {
    /// Creates `task`'s stdio pipes in `authority`, pumps between them and `host`, and returns the
    /// descriptors `task` inherits.
    pub(crate) fn start(
        authority: &Arc<BrokerProcess>,
        wake: &Arc<Wake>,
        task: &BrokerProcess,
        host: Host,
    ) -> io::Result<(Self, Vec<InheritedFd>)> {
        let io = Self {
            stdin: Control::new()?,
            outputs: [Control::new()?, Control::new()?],
            wake: Arc::clone(wake),
        };
        let broker = |error: BrokerError| io::Error::other(format!("stdio pipes: {error}"));
        let mut handles = Vec::new();
        let created = (|| {
            for _ in 0..3 {
                let (read, write) = pipe::create(
                    authority,
                    PIPE_CAPACITY,
                    PIPE_ATOMIC_WRITE,
                    FileOpenFlags::NONE,
                )
                .map_err(broker)?;
                handles.extend([read, write]);
            }
            let guest_ends = [handles[0], handles[3], handles[5]];
            let guest = authority
                .duplicate_object_references_to(&guest_ends, task)
                .map_err(broker)?;
            // The task's references must be the only ones to its ends, or no end of file ever
            // reaches either side.
            for handle in guest_ends {
                authority.close_object_reference(handle).map_err(broker)?;
                handles.retain(|kept| *kept != handle);
            }
            // Registration covers only the references that exist now.
            let sink: Arc<dyn ReadinessSink> = Arc::<Wake>::clone(wake);
            authority.register_readiness(&sink).map_err(broker)?;
            Ok(guest)
        })();
        let guest = match created {
            Ok(guest) => guest,
            Err(error) => {
                for handle in handles {
                    let _ = authority.close_object_reference(handle);
                }
                return Err(error);
            }
        };
        let Host { fds: host, logger } = host;
        let logger = logger.map(Arc::new);
        let streams = [
            (handles[0], Arc::clone(&io.stdin)),
            (handles[1], Arc::clone(&io.outputs[0])),
            (handles[2], Arc::clone(&io.outputs[1])),
        ];
        for (index, ((handle, control), host)) in streams.into_iter().zip(host).enumerate() {
            let (pump_authority, wake) = (Arc::clone(authority), Arc::clone(wake));
            // The output pumps hold the logging binary, which the last one to end reaps.
            let logger = logger.clone().filter(|_| index > 0);
            let spawned = std::thread::Builder::new()
                .name("litebox-stdio".to_owned())
                .spawn(move || {
                    if index == 0 {
                        copy_input(&pump_authority, &wake, handle, &host, &control);
                    } else {
                        copy_output(&pump_authority, &wake, handle, &host, &control);
                    }
                    drop(host);
                    let _ = pump_authority.close_object_reference(handle);
                    control.finish();
                    drop(logger);
                });
            if let Err(error) = spawned {
                // Pumps that never started leave their references to the authority.
                io.abort();
                for handle in handles.iter().skip(index) {
                    let _ = authority.close_object_reference(*handle);
                }
                return Err(error);
            }
        }
        let ends = [
            HalfPipeType::ReceiverHalf,
            HalfPipeType::SenderHalf,
            HalfPipeType::SenderHalf,
        ];
        let inherited = (0..)
            .zip(guest.into_iter().zip(ends))
            .map(|(fd, (handle, endpoint))| InheritedFd {
                fd,
                handle,
                kind: InheritedFdKind::Pipe { endpoint },
            })
            .collect();
        Ok((io, inherited))
    }

    /// Forwards the input that is already readable, then ends the task's stdin.
    pub(crate) fn close_stdin(&self) {
        self.stdin.request(Mode::Close, &self.wake);
    }

    /// Stops every pump.
    pub(crate) fn abort(&self) {
        for control in std::iter::once(&self.stdin).chain(&self.outputs) {
            control.request(Mode::Abort, &self.wake);
        }
    }

    /// Ends the streams of a task that exited: stops its input, and waits up to `timeout` for
    /// its output to reach its end, which a surviving child holding it can delay, before
    /// stopping the output pumps too.
    pub(crate) fn finish(&self, timeout: Duration) {
        self.stdin.request(Mode::Abort, &self.wake);
        let deadline = Instant::now() + timeout;
        if !self.outputs.iter().all(|output| output.wait(deadline)) {
            log::warn!("the output of a process did not end in time");
            self.abort();
            let deadline = Instant::now() + ABORT_TIMEOUT;
            for output in &self.outputs {
                output.wait(deadline);
            }
        }
    }
}

/// The pumps hold their own controls, so they would outlive their task otherwise.
impl Drop for TaskIo {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Waits until `host` is ready for `flags`, returning `false` instead once `control` changes
/// mode or the wait fails.
fn wait_host(host: &OwnedFd, flags: PollFlags, control: &Control) -> bool {
    let mut fds = [
        PollFd::new(host, flags),
        PollFd::new(&control.event, PollFlags::IN),
    ];
    loop {
        match rustix::event::poll(&mut fds, None) {
            Ok(_) => return fds[1].revents().is_empty(),
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return false,
        }
    }
}

fn copy_input(
    authority: &BrokerProcess,
    wake: &Wake,
    handle: ObjectHandle,
    host: &OwnedFd,
    control: &Control,
) {
    let mut buffer = vec![0; CHUNK];
    // Once `CloseIO` is seen, what remains of the input that was pending then: input that arrives
    // later is not forwarded, or a producer that never stops would keep the stream open.
    let mut closing: Option<usize> = None;
    loop {
        match control.mode() {
            Mode::Run if !wait_host(host, PollFlags::IN, control) => continue,
            Mode::Run => {}
            Mode::Close => {
                let left = *closing.get_or_insert_with(|| {
                    rustix::io::ioctl_fionread(host)
                        .map_or(0, |pending| usize::try_from(pending).unwrap_or(usize::MAX))
                });
                if left == 0 {
                    return;
                }
            }
            Mode::Abort => return,
        }
        let limit = closing.map_or(CHUNK, |left| left.min(CHUNK));
        let read = match rustix::io::read(host, &mut buffer[..limit]) {
            Ok(0) => return,
            Ok(read) => read,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR)
                if control.mode() == Mode::Run =>
            {
                continue;
            }
            Err(_) => return,
        };
        if let Some(left) = &mut closing {
            *left -= read;
        }
        let mut data = &buffer[..read];
        while !data.is_empty() {
            let seen = wake.generation();
            match pipe::write(authority, handle, &data) {
                Ok(written) => data = &data[written..],
                Err(BrokerError::WouldBlock) if control.mode() != Mode::Abort => wake.wait(seen),
                Err(_) => return,
            }
        }
    }
}

fn copy_output(
    authority: &BrokerProcess,
    wake: &Wake,
    handle: ObjectHandle,
    host: &OwnedFd,
    control: &Control,
) {
    let mut buffer = vec![0; CHUNK];
    while control.mode() != Mode::Abort {
        let seen = wake.generation();
        let read = match pipe::read(authority, handle, &mut buffer) {
            Ok(0) => return,
            Ok(read) => read,
            Err(BrokerError::WouldBlock) => {
                wake.wait(seen);
                continue;
            }
            Err(_) => return,
        };
        let mut data = &buffer[..read];
        while !data.is_empty() {
            match rustix::io::write(host, data) {
                Ok(written) => data = &data[written..],
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    if !wait_host(host, PollFlags::OUT, control) {
                        return;
                    }
                }
                // The output is gone: the task's next write fails as on a broken pipe.
                Err(_) => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uris_open_without_blocking_or_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let fifo = fifo.to_str().unwrap();
        let log = dir.path().join("out.log");
        let log = log.to_str().unwrap();

        // No peer holds the FIFO open, which a blocking open would wait for.
        let open = |stdin: &str, stdout: &str, stderr: &str| {
            open(stdin, stdout, stderr, "c", "ns", &Arc::default()).map(|host| host.fds)
        };
        let [_, stdout, _] =
            open(fifo, &format!("file://{log}"), &format!("fifo://{fifo}")).unwrap();
        rustix::io::write(&stdout, b"out").unwrap();
        assert_eq!(std::fs::read_to_string(log).unwrap(), "out");
        open("", "", "").unwrap();
        // containerd escapes URI paths.
        let escaped = format!("file://{}/a%20b%25.log", dir.path().display());
        let [_, stdout, _] = open("", &escaped, "").unwrap();
        rustix::io::write(&stdout, b"escaped").unwrap();
        let unescaped = dir.path().join("a b%.log");
        assert_eq!(std::fs::read_to_string(unescaped).unwrap(), "escaped");

        for (stdin, stdout) in [
            (format!("file://{log}"), String::new()),
            ("binary:///bin/true".to_owned(), String::new()),
            (String::new(), "binary://relative".to_owned()),
            (String::new(), format!("file://{log}?x=1")),
            (String::new(), format!("file://{log}#x")),
            (String::new(), format!("file://{log}%2")),
            (String::new(), format!("file://{log}%zz")),
            (String::new(), "relative".to_owned()),
            (log.to_owned(), String::new()),
        ] {
            let error = open(&stdin, &stdout, "").unwrap_err();
            assert_eq!(
                error.kind,
                crate::error::Kind::InvalidArgument,
                "{stdin} {stdout}"
            );
        }
        // Opening a FIFO without a reader to write only would block.
        assert!(open("", &format!("file://{fifo}"), "").is_err());
    }
}
